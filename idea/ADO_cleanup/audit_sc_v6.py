#!/usr/bin/env python3
"""
GIC_63623 - ADO Service Connection Audit + Pipeline Mapping
Accurate version:
- Works for YAML and Classic pipelines
- Uses execution history for counts only
- Uses exact structured definition scan for current pipeline mapping
- Avoids false positives from broad substring matching
"""

import argparse
import base64
import csv
import getpass
import json
import sys
from datetime import datetime

try:
    import requests
except ImportError:
    print("ERROR: requests library not found.")
    print("Install with: pip3 install requests --user")
    sys.exit(1)

DSS_PREFIX = "dss_devops"

KNOWN_CONNECTIONS = [
    "artifactory_cdb", "artifactory_publish", "artifactory_qa",
    "BMO-Prod (6)", "chsArtifactoryServiceConnection", "chsSonarQubeServiceConnection",
    "dss_devops_sc_artifactory", "dss_devops_sc_artifactory_platform",
    "dss_devops_sc_openshift_water", "dss_devops_sc_sonarqube",
    "GIC_63623_SonarQube", "github.com_sa-onboarding_bmogc-Belle_Isle",
    "Frog_gic", "Frog_gic_Saas", "jfrog-artifactory", "jfrog-connection",
    "jfrog-connection-publish", "Jfrog-gic", "SPLAT_Components_24757",
    "svc_bwa_dev01", "test_connection", "Testing-artifactory-token"
]

USAGE_KEYS = {
    "endpoint",
    "endpointid",
    "serviceconnection",
    "serviceconnectionid",
    "serviceconnectionname",
    "serviceendpoint",
    "serviceendpointid",
    "connectedservice",
    "connectedserviceid",
    "connectedservicename",
    "connectedservicearm",
    "connectedserviceazurerm",
    "azuresubscription",
    "azureSubscription".lower(),
    "containerregistry",
    "dockerregistryserviceconnection",
    "kubernetesserviceconnection",
    "sonarconnection",
    "sonarqube",
    "artifactoryservice",
    "artifactoryconnection",
    "jfrogserviceconnection",
    "target_artifactory_connection",
    "source_artifactory_connection",
    "connection"
}

def get_headers(pat):
    encoded = base64.b64encode(f":{pat}".encode("ascii")).decode("ascii")
    return {
        "Authorization": f"Basic {encoded}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

def ado_get(url, headers):
    try:
        r = requests.get(url, headers=headers, timeout=90)
        r.raise_for_status()
        ctype = r.headers.get("Content-Type", "")
        if "application/json" in ctype:
            return r.json()
        return r.text
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response is not None else "UNKNOWN"
        print(f"  WARNING HTTP {code}: {url}", flush=True)
        return None
    except Exception as e:
        print(f"  WARNING Request failed: {url} -> {e}", flush=True)
        return None

def safe_get(dct, *keys):
    cur = dct
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
        if cur is None:
            return None
    return cur

def normalize(value):
    if value is None:
        return ""
    return str(value).strip()

def exact_eq(a, b):
    return normalize(a).lower() == normalize(b).lower()

def detect_service_connection_refs(obj, sc_name, sc_id, found_matches, path_parts=None):
    if path_parts is None:
        path_parts = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k)
            key_l = key_str.lower()
            current_path = path_parts + [key_str]

            # recurse first
            if isinstance(v, (dict, list)):
                detect_service_connection_refs(v, sc_name, sc_id, found_matches, current_path)
            else:
                value = normalize(v)

                # 1. Exact ID match anywhere
                if sc_id and exact_eq(value, sc_id):
                    found_matches.append({
                        "Path": ".".join(current_path),
                        "MatchType": "ExactIdMatch",
                        "MatchedKey": key_str,
                        "MatchedValue": value
                    })
                    continue

                # 2. Exact name match only in allowed usage keys
                if sc_name and key_l in USAGE_KEYS and exact_eq(value, sc_name):
                    found_matches.append({
                        "Path": ".".join(current_path),
                        "MatchType": "ExactNameMatch_UsageKey",
                        "MatchedKey": key_str,
                        "MatchedValue": value
                    })
                    continue

                # 3. Special case for repository resources endpoint
                path_l = [p.lower() for p in path_parts]
                if (
                    sc_name and
                    key_l == "endpoint" and
                    exact_eq(value, sc_name) and
                    "resources" in path_l and
                    "repositories" in path_l
                ):
                    found_matches.append({
                        "Path": ".".join(current_path),
                        "MatchType": "ExactNameMatch_RepoEndpoint",
                        "MatchedKey": key_str,
                        "MatchedValue": value
                    })
                    continue

                # 4. Template/job/task inputs and parameters only if exact key/value match
                if (
                    sc_name and
                    exact_eq(value, sc_name) and
                    ("inputs" in [p.lower() for p in path_parts] or "parameters" in [p.lower() for p in path_parts])
                ):
                    found_matches.append({
                        "Path": ".".join(current_path),
                        "MatchType": "ExactNameMatch_InputsOrParameters",
                        "MatchedKey": key_str,
                        "MatchedValue": value
                    })

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            detect_service_connection_refs(item, sc_name, sc_id, found_matches, path_parts + [f"[{idx}]"])

def classify(is_dss, pipeline_count, is_known, times_used):
    if is_dss:
        return "KEEP - DSS Standard"
    if pipeline_count > 0 or times_used > 0:
        return "REVIEW - In use, non-standard"
    if is_known:
        return "CANDIDATE FOR REMOVAL - No pipeline evidence found"
    return "REVIEW - Unknown connection"

def main():
    parser = argparse.ArgumentParser(description="ADO Service Connection Audit + Pipeline Mapping")
    parser.add_argument("--org", required=False)
    parser.add_argument("--project", required=False)
    parser.add_argument("--output-prefix", required=False, default="")
    args = parser.parse_args()

    print("Starting audit_service_connection.py", flush=True)

    org = args.org or input("Enter your ADO Organization name: ").strip()
    project_name = args.project or input("Enter project name (e.g. GIC_63623): ").strip()

    print("Enter PAT: ", end="", flush=True)
    pat = getpass.getpass("")

    if not org or not project_name or not pat:
        print("ERROR: org, project, and PAT are required.", flush=True)
        sys.exit(1)

    ts = datetime.now().strftime("%Y%m%d_%H%M")
    prefix = args.output_prefix or f"{project_name}_{ts}"

    audit_csv = f"{prefix}_service_connection_audit.csv"
    sc_to_pipe_csv = f"{prefix}_service_connection_to_pipelines.csv"
    pipe_to_sc_csv = f"{prefix}_pipeline_to_service_connections.csv"
    raw_evidence_csv = f"{prefix}_raw_evidence.csv"

    headers = get_headers(pat)
    base_url = f"https://dev.azure.com/{org}"

    print(f"\nScanning project: {project_name}", flush=True)

    # 1. Service connections
    print("[1/4] Fetching service connections...", flush=True)
    sc_url = f"{base_url}/{project_name}/_apis/serviceendpoint/endpoints?includeDetails=true&api-version=7.1"
    sc_data = ado_get(sc_url, headers)
    if not sc_data:
        print("ERROR: Failed to retrieve service connections.", flush=True)
        sys.exit(1)

    service_connections = sc_data.get("value", [])
    print(f"  Found {len(service_connections)} service connections.", flush=True)

    sc_by_name = {}
    for sc in service_connections:
        sc_name = normalize(sc.get("name"))
        if sc_name:
            sc_by_name[sc_name] = sc

    # 2. Build definitions
    print("[2/4] Fetching build definitions...", flush=True)
    defs_url = f"{base_url}/{project_name}/_apis/build/definitions?api-version=7.1&$top=500"
    defs_data = ado_get(defs_url, headers)
    if not defs_data:
        print("ERROR: Failed to retrieve build definitions.", flush=True)
        sys.exit(1)

    build_defs = defs_data.get("value", [])
    print(f"  Found {len(build_defs)} build definitions.", flush=True)

    sc_to_pipelines = {name: set() for name in sc_by_name.keys()}
    pipeline_to_scs = {}
    times_used_by_sc = {}
    last_used_by_sc = {}
    raw_evidence_rows = []

    # 3. Accurate definition scan only
    print("[3/4] Scanning build definitions with exact matching...", flush=True)
    for bd in build_defs:
        def_id = str(bd.get("id", "")).strip()
        def_name = normalize(bd.get("name"))

        print(f"  -> {def_name}", flush=True)

        detail_url = f"{base_url}/{project_name}/_apis/build/definitions/{def_id}?api-version=7.1"
        detail = ado_get(detail_url, headers)
        if not detail:
            continue

        for sc_name, sc in sc_by_name.items():
            sc_id = normalize(sc.get("id"))
            found_matches = []
            detect_service_connection_refs(detail, sc_name, sc_id, found_matches)

            if found_matches:
                sc_to_pipelines[sc_name].add(def_name)
                pipeline_to_scs.setdefault(def_name, set()).add(sc_name)

                for m in found_matches:
                    raw_evidence_rows.append({
                        "Project": project_name,
                        "ServiceConnectionName": sc_name,
                        "ServiceConnectionId": sc_id,
                        "EvidenceType": m["MatchType"],
                        "PipelineName": def_name,
                        "BuildDefinitionId": def_id,
                        "Detail": m["Path"],
                        "MatchedKey": m["MatchedKey"],
                        "MatchedValue": m["MatchedValue"]
                    })

    # 4. Execution history for counts only
    print("[4/4] Reading execution history for counts...", flush=True)
    for sc_name, sc in sc_by_name.items():
        sc_id = normalize(sc.get("id"))
        hist_url = f"{base_url}/{project_name}/_apis/serviceendpoint/{sc_id}/executionhistory?top=500&api-version=7.0"
        hist = ado_get(hist_url, headers)

        if hist and hist.get("count", 0) > 0:
            items = hist.get("value", [])
            times_used_by_sc[sc_name] = len(items)

            latest = ""
            for item in items:
                finish = safe_get(item, "data", "finishTime")
                if isinstance(finish, str) and finish and finish > latest:
                    latest = finish

            last_used_by_sc[sc_name] = latest[:10] if latest else "Unknown"
        else:
            times_used_by_sc[sc_name] = 0
            last_used_by_sc[sc_name] = "Never"

    # Reverse map
    for sc_name, pipe_set in sc_to_pipelines.items():
        for pipe in pipe_set:
            pipeline_to_scs.setdefault(pipe, set()).add(sc_name)

    # Audit rows
    audit_rows = []
    for sc_name, sc in sc_by_name.items():
        pipes = sorted(sc_to_pipelines.get(sc_name, set()))
        pipeline_count = len(pipes)
        is_dss = sc_name.startswith(DSS_PREFIX)
        is_known = sc_name in KNOWN_CONNECTIONS

        audit_rows.append({
            "Project": project_name,
            "ConnectionName": sc_name,
            "ConnectionID": sc.get("id", ""),
            "Type": sc.get("type", ""),
            "IsShared": sc.get("isShared", False),
            "IsDssStandard": is_dss,
            "IsReady": sc.get("isReady", False),
            "TimesUsed_Last500": times_used_by_sc.get(sc_name, 0),
            "LastUsedDate": last_used_by_sc.get(sc_name, "Never"),
            "PipelineCount": pipeline_count,
            "PipelinesUsing": " | ".join(pipes),
            "AuthScheme": safe_get(sc, "authorization", "scheme") or "",
            "CreatedBy": safe_get(sc, "createdBy", "displayName") or "",
            "Description": sc.get("description", ""),
            "Recommendation": classify(is_dss, pipeline_count, is_known, times_used_by_sc.get(sc_name, 0))
        })

    # SC -> pipelines
    sc_to_pipe_rows = []
    for sc_name in sorted(sc_by_name.keys(), key=lambda x: x.lower()):
        sc_obj = sc_by_name[sc_name]
        pipes = sorted(sc_to_pipelines.get(sc_name, set()))
        sc_to_pipe_rows.append({
            "Project": project_name,
            "ServiceConnectionName": sc_name,
            "ServiceConnectionId": sc_obj.get("id", ""),
            "Type": sc_obj.get("type", ""),
            "IsShared": sc_obj.get("isShared", False),
            "PipelineCount": len(pipes),
            "PipelinesUsing": " | ".join(pipes),
            "TimesUsed": times_used_by_sc.get(sc_name, 0),
            "LastUsedDate": last_used_by_sc.get(sc_name, "Never")
        })

    # Pipeline -> SCs
    pipe_to_sc_rows = []
    for bd in sorted(build_defs, key=lambda x: x.get("name", "").lower()):
        def_name = normalize(bd.get("name"))
        def_id = bd.get("id", "")
        scs = sorted(pipeline_to_scs.get(def_name, set()))
        pipe_to_sc_rows.append({
            "Project": project_name,
            "PipelineId": def_id,
            "PipelineName": def_name,
            "ServiceConnectionCount": len(scs),
            "ServiceConnectionsUsed": " | ".join(scs)
        })

    # Dedup raw evidence
    raw_dedup = {}
    for row in raw_evidence_rows:
        key = (
            row["ServiceConnectionName"],
            row["EvidenceType"],
            row["PipelineName"],
            str(row["BuildDefinitionId"]),
            str(row["Detail"]),
            str(row["MatchedKey"]),
            str(row["MatchedValue"])
        )
        raw_dedup[key] = row
    raw_evidence_rows = list(raw_dedup.values())

    # Write files
    with open(audit_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(audit_rows[0].keys()))
        writer.writeheader()
        writer.writerows(sorted(audit_rows, key=lambda x: x["ConnectionName"].lower()))

    with open(sc_to_pipe_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(sc_to_pipe_rows[0].keys()))
        writer.writeheader()
        writer.writerows(sc_to_pipe_rows)

    with open(pipe_to_sc_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(pipe_to_sc_rows[0].keys()))
        writer.writeheader()
        writer.writerows(pipe_to_sc_rows)

    with open(raw_evidence_csv, "w", newline="", encoding="utf-8") as f:
        if raw_evidence_rows:
            writer = csv.DictWriter(f, fieldnames=list(raw_evidence_rows[0].keys()))
            writer.writeheader()
            writer.writerows(sorted(
                raw_evidence_rows,
                key=lambda x: (
                    x["ServiceConnectionName"].lower(),
                    x["PipelineName"].lower(),
                    x["EvidenceType"].lower()
                )
            ))
        else:
            writer = csv.writer(f)
            writer.writerow([
                "Project", "ServiceConnectionName", "ServiceConnectionId",
                "EvidenceType", "PipelineName", "BuildDefinitionId", "Detail",
                "MatchedKey", "MatchedValue"
            ])

    print("\nDone.", flush=True)
    print(f"Audit CSV                  : {audit_csv}", flush=True)
    print(f"SC -> Pipelines CSV        : {sc_to_pipe_csv}", flush=True)
    print(f"Pipeline -> SC CSV         : {pipe_to_sc_csv}", flush=True)
    print(f"Raw Evidence CSV           : {raw_evidence_csv}", flush=True)

    print("\nPreview:", flush=True)
    for row in sorted(sc_to_pipe_rows, key=lambda x: (-x["PipelineCount"], x["ServiceConnectionName"].lower()))[:10]:
        print(f"  {row['ServiceConnectionName']}: {row['PipelineCount']} pipeline(s)", flush=True)

if __name__ == "__main__":
    main()
