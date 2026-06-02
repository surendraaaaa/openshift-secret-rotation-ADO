#!/usr/bin/env python3
"""
GIC_63623 - Accurate Azure DevOps Service Connection Usage Audit

Goal:
- For each service connection, list the pipelines CURRENTLY using it
- Work for both YAML and Classic build pipelines
- Avoid false positives from loose text scanning
- Use build definitions as source of truth
- Use execution history only as supporting metadata, not for pipeline mapping

Outputs:
1. <prefix>_service_connection_to_pipelines.csv
2. <prefix>_pipeline_to_service_connections.csv
3. <prefix>_service_connection_audit.csv
4. <prefix>_raw_definition_matches.csv
"""

import argparse
import base64
import csv
import getpass
import json
import re
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
    "connectedservice",
    "connectedservicearm",
    "connectedserviceazurerm",
    "connectedservicename",
    "serviceconnection",
    "serviceconnectionname",
    "serviceendpoint",
    "serviceendpointid",
    "endpoint",
    "endpointid",
    "azuresubscription",
    "azureSubscription".lower(),
    "containerregistry",
    "dockerregistryserviceconnection",
    "kubernetesserviceconnection",
    "sonarqube",
    "sonarconnection",
    "artifactoryservice",
    "artifactory_service",
    "artifactoryconnection",
    "jfrogserviceconnection",
    "target_artifactory_connection",
    "source_artifactory_connection",
    "npmserviceconnection",
    "helmserviceconnection",
    "nugetserviceconnection",
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

def normalize_text(s):
    if s is None:
        return ""
    return str(s).strip()

def exact_name_match(value, sc_name):
    return normalize_text(value).lower() == normalize_text(sc_name).lower()

def exact_id_match(value, sc_id):
    return normalize_text(value).lower() == normalize_text(sc_id).lower()

def maybe_repo_endpoint_match(path_parts, key, value, sc_name):
    # For YAML repository resources:
    # resources.repositories[*].endpoint: github.com_sa-onboarding...
    path_text = ".".join(path_parts).lower()
    return (
        "resources" in path_text and
        "repositories" in path_text and
        key.lower() == "endpoint" and
        exact_name_match(value, sc_name)
    )

def scan_structure(obj, sc_name, sc_id, path_parts=None, matches=None):
    if path_parts is None:
        path_parts = []
    if matches is None:
        matches = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            current_path = path_parts + [str(k)]
            key_l = str(k).lower()

            if isinstance(v, (dict, list)):
                scan_structure(v, sc_name, sc_id, current_path, matches)
            else:
                val = normalize_text(v)

                matched = False
                reason = ""

                # Exact ID match in any string value
                if sc_id and exact_id_match(val, sc_id):
                    matched = True
                    reason = "ExactIdMatch"

                # Exact name match only in likely usage keys / repo endpoint / template param keys
                elif sc_name:
                    if key_l in USAGE_KEYS and exact_name_match(val, sc_name):
                        matched = True
                        reason = "ExactNameMatch_UsageKey"
                    elif maybe_repo_endpoint_match(current_path, str(k), val, sc_name):
                        matched = True
                        reason = "ExactNameMatch_RepoEndpoint"
                    elif ("parameters" in [p.lower() for p in path_parts] or "inputs" in [p.lower() for p in path_parts]) and exact_name_match(val, sc_name):
                        matched = True
                        reason = "ExactNameMatch_ParametersOrInputs"

                if matched:
                    matches.append({
                        "Path": ".".join(current_path),
                        "Key": str(k),
                        "Value": val,
                        "Reason": reason
                    })

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            scan_structure(item, sc_name, sc_id, path_parts + [f"[{idx}]"], matches)

    return matches

def classify(is_dss, pipeline_count, is_known):
    if is_dss:
        return "KEEP - DSS Standard"
    if pipeline_count > 0:
        return "REVIEW - In use, non-standard"
    if is_known:
        return "CANDIDATE FOR REMOVAL - No current pipeline reference found"
    return "REVIEW - Unknown connection"

def get_execution_history_usage(base_url, project_name, sc_id, headers):
    hist_url = f"{base_url}/{project_name}/_apis/serviceendpoint/{sc_id}/executionhistory?top=500&api-version=7.0"
    hist = ado_get(hist_url, headers)

    if hist and isinstance(hist, dict) and hist.get("count", 0) > 0:
        items = hist.get("value", [])
        latest = ""
        for item in items:
            finish = (((item.get("data") or {}).get("finishTime")) or "")
            if finish and finish > latest:
                latest = finish
        return len(items), (latest[:10] if latest else "Unknown")
    return 0, "Never"

def main():
    parser = argparse.ArgumentParser(description="Accurate ADO Service Connection Usage Audit")
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

    sc_to_pipe_csv = f"{prefix}_service_connection_to_pipelines.csv"
    pipe_to_sc_csv = f"{prefix}_pipeline_to_service_connections.csv"
    audit_csv = f"{prefix}_service_connection_audit.csv"
    raw_csv = f"{prefix}_raw_definition_matches.csv"

    headers = get_headers(pat)
    base_url = f"https://dev.azure.com/{org}"

    print(f"\nScanning project: {project_name}", flush=True)

    print("[1/4] Fetching service connections...", flush=True)
    sc_url = f"{base_url}/{project_name}/_apis/serviceendpoint/endpoints?includeDetails=true&api-version=7.1"
    sc_data = ado_get(sc_url, headers)
    if not sc_data:
        print("ERROR: Failed to retrieve service connections.", flush=True)
        sys.exit(1)

    service_connections = sc_data.get("value", [])
    print(f"  Found {len(service_connections)} service connections.", flush=True)

    print("[2/4] Fetching build definitions...", flush=True)
    defs_url = f"{base_url}/{project_name}/_apis/build/definitions?api-version=7.1&$top=500"
    defs_data = ado_get(defs_url, headers)
    if not defs_data:
        print("ERROR: Failed to retrieve build definitions.", flush=True)
        sys.exit(1)

    build_defs = defs_data.get("value", [])
    print(f"  Found {len(build_defs)} build definitions.", flush=True)

    sc_to_pipelines = {}
    pipeline_to_scs = {}
    raw_rows = []

    for sc in service_connections:
        sc_name = normalize_text(sc.get("name"))
        sc_to_pipelines[sc_name] = set()

    print("[3/4] Scanning definitions accurately for current references...", flush=True)
    for idx, bd in enumerate(build_defs, start=1):
        def_id = str(bd.get("id", "")).strip()
        def_name = normalize_text(bd.get("name"))

        print(f"  [{idx}/{len(build_defs)}] {def_name}", flush=True)

        detail_url = f"{base_url}/{project_name}/_apis/build/definitions/{def_id}?api-version=7.1"
        detail = ado_get(detail_url, headers)
        if not detail or not isinstance(detail, dict):
            continue

        for sc in service_connections:
            sc_name = normalize_text(sc.get("name"))
            sc_id = normalize_text(sc.get("id"))

            matches = scan_structure(detail, sc_name, sc_id)

            if matches:
                sc_to_pipelines.setdefault(sc_name, set()).add(def_name)
                pipeline_to_scs.setdefault(def_name, set()).add(sc_name)

                for m in matches:
                    raw_rows.append({
                        "Project": project_name,
                        "PipelineId": def_id,
                        "PipelineName": def_name,
                        "ServiceConnectionName": sc_name,
                        "ServiceConnectionId": sc_id,
                        "MatchReason": m["Reason"],
                        "JsonPath": m["Path"],
                        "MatchedKey": m["Key"],
                        "MatchedValue": m["Value"]
                    })

    print("[4/4] Fetching execution history counts...", flush=True)
    times_used_by_sc = {}
    last_used_by_sc = {}
    for sc in service_connections:
        sc_name = normalize_text(sc.get("name"))
        sc_id = normalize_text(sc.get("id"))
        count, last_used = get_execution_history_usage(base_url, project_name, sc_id, headers)
        times_used_by_sc[sc_name] = count
        last_used_by_sc[sc_name] = last_used

    sc_to_pipe_rows = []
    audit_rows = []

    for sc in sorted(service_connections, key=lambda x: normalize_text(x.get("name")).lower()):
        sc_name = normalize_text(sc.get("name"))
        sc_id = normalize_text(sc.get("id"))
        pipes = sorted(sc_to_pipelines.get(sc_name, set()))
        pipeline_count = len(pipes)
        is_dss = sc_name.startswith(DSS_PREFIX)
        is_known = sc_name in KNOWN_CONNECTIONS

        sc_to_pipe_rows.append({
            "Project": project_name,
            "ServiceConnectionName": sc_name,
            "ServiceConnectionId": sc_id,
            "Type": normalize_text(sc.get("type")),
            "IsShared": sc.get("isShared", False),
            "PipelineCount": pipeline_count,
            "PipelinesUsing": " | ".join(pipes),
            "TimesUsed": times_used_by_sc.get(sc_name, 0),
            "LastUsedDate": last_used_by_sc.get(sc_name, "Never")
        })

        audit_rows.append({
            "Project": project_name,
            "ConnectionName": sc_name,
            "ConnectionID": sc_id,
            "Type": normalize_text(sc.get("type")),
            "IsShared": sc.get("isShared", False),
            "IsDssStandard": is_dss,
            "IsReady": sc.get("isReady", False),
            "TimesUsed_Last500": times_used_by_sc.get(sc_name, 0),
            "LastUsedDate": last_used_by_sc.get(sc_name, "Never"),
            "PipelineCount": pipeline_count,
            "PipelinesUsing": " | ".join(pipes),
            "AuthScheme": ((sc.get("authorization") or {}).get("scheme") or ""),
            "CreatedBy": ((sc.get("createdBy") or {}).get("displayName") or ""),
            "Description": normalize_text(sc.get("description")),
            "Recommendation": classify(is_dss, pipeline_count, is_known)
        })

    pipe_to_sc_rows = []
    for bd in sorted(build_defs, key=lambda x: normalize_text(x.get("name")).lower()):
        def_name = normalize_text(bd.get("name"))
        def_id = str(bd.get("id", "")).strip()
        scs = sorted(pipeline_to_scs.get(def_name, set()))
        pipe_to_sc_rows.append({
            "Project": project_name,
            "PipelineId": def_id,
            "PipelineName": def_name,
            "ServiceConnectionCount": len(scs),
            "ServiceConnectionsUsed": " | ".join(scs)
        })

    # de-dup raw rows
    dedup = {}
    for row in raw_rows:
        key = (
            row["PipelineId"],
            row["PipelineName"],
            row["ServiceConnectionId"],
            row["MatchReason"],
            row["JsonPath"],
            row["MatchedValue"]
        )
        dedup[key] = row
    raw_rows = list(dedup.values())

    with open(sc_to_pipe_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(sc_to_pipe_rows[0].keys()))
        writer.writeheader()
        writer.writerows(sc_to_pipe_rows)

    with open(pipe_to_sc_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(pipe_to_sc_rows[0].keys()))
        writer.writeheader()
        writer.writerows(pipe_to_sc_rows)

    with open(audit_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(audit_rows[0].keys()))
        writer.writeheader()
        writer.writerows(audit_rows)

    with open(raw_csv, "w", newline="", encoding="utf-8") as f:
        if raw_rows:
            writer = csv.DictWriter(f, fieldnames=list(raw_rows[0].keys()))
            writer.writeheader()
            writer.writerows(sorted(
                raw_rows,
                key=lambda x: (
                    x["ServiceConnectionName"].lower(),
                    x["PipelineName"].lower(),
                    x["JsonPath"].lower()
                )
            ))
        else:
            writer = csv.writer(f)
            writer.writerow([
                "Project", "PipelineId", "PipelineName", "ServiceConnectionName",
                "ServiceConnectionId", "MatchReason", "JsonPath", "MatchedKey", "MatchedValue"
            ])

    print("\nDone.", flush=True)
    print(f"SC -> Pipelines CSV   : {sc_to_pipe_csv}", flush=True)
    print(f"Pipeline -> SC CSV    : {pipe_to_sc_csv}", flush=True)
    print(f"Audit CSV             : {audit_csv}", flush=True)
    print(f"Raw Match CSV         : {raw_csv}", flush=True)

    print("\nTop results:", flush=True)
    for row in sorted(sc_to_pipe_rows, key=lambda x: (-x["PipelineCount"], x["ServiceConnectionName"].lower()))[:10]:
        print(f"  {row['ServiceConnectionName']}: {row['PipelineCount']} pipeline(s)", flush=True)

if __name__ == "__main__":
    main()
