#!/usr/bin/env python3
"""
GIC_63623 - ADO Service Connection Audit + Usage Mapping
Python 3.9 compatible
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
    print("ERROR: requests library not found.", flush=True)
    print("Install with: pip3 install requests --user", flush=True)
    sys.exit(1)

DSS_PREFIX = "dss_devops"

KNOWN_CONNECTIONS = [
    "artifactory_cdb", "artifactory_publish", "artifactory_qa",
    "BMO-Prod (6)", "chsArtifactoryServiceConnection", "chsSonarQubeServiceConnection",
    "dss_devops_sc_artifactory", "dss_devops_s_artifactory_platform",
    "dss_devops_s_openshift_water", "dss_devops_sc_sonarqube",
    "GIC_63623_SonarQube", "github.com_sa-onboarding_bmogc-Belle_Isle",
    "Frog_gic", "Frog_gic_Saas", "jfrog-artifactory", "jfrog-connection",
    "jfrog-connection-publish", "Jfrog-gic", "SPLAT_Components_24757",
    "svc_bwa_dev01", "test_connection", "Testing-artifactory-token"
]

def get_headers(pat):
    encoded = base64.b64encode(f":{pat}".encode("ascii")).decode("ascii")
    return {
        "Authorization": f"Basic {encoded}",
        "Accept": "application/json",
    }

def ado_get(url, headers):
    try:
        r = requests.get(url, headers=headers, timeout=60)
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

def classify(is_dss, pipeline_count, is_known):
    if is_dss:
        return "KEEP - DSS Standard"
    if pipeline_count > 0:
        return "REVIEW - In use, non-standard"
    if is_known:
        return "CANDIDATE FOR REMOVAL - Not found in definition scan"
    return "REVIEW - Unknown connection"

def main():
    parser = argparse.ArgumentParser(description="ADO Service Connection Audit + Usage Mapping")
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
    raw_map_csv = f"{prefix}_raw_mapping.csv"

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
    print(f"Found {len(service_connections)} service connections.", flush=True)

    sc_by_name = {}
    for sc in service_connections:
        sc_name = sc.get("name", "")
        sc_by_name[sc_name] = sc

    # 2. Build definitions
    print("[2/4] Fetching build definitions...", flush=True)
    defs_url = f"{base_url}/{project_name}/_apis/build/definitions?api-version=7.1&$top=500"
    defs_data = ado_get(defs_url, headers)
    if not defs_data:
        print("ERROR: Failed to retrieve build definitions.", flush=True)
        sys.exit(1)

    build_defs = defs_data.get("value", [])
    print(f"Found {len(build_defs)} build definitions.", flush=True)

    raw_map_rows = []
    sc_to_pipelines = {}
    pipeline_to_scs = {}

    # 3. Scan definitions
    print("[3/4] Scanning build definitions for service connection references...", flush=True)
    for bd in build_defs:
        def_id = bd.get("id", "")
        def_name = bd.get("name", "")

        print(f"-> Definition: {def_name} (id={def_id})", flush=True)

        detail_url = f"{base_url}/{project_name}/_apis/build/definitions/{def_id}?api-version=7.1"
        detail = ado_get(detail_url, headers)
        if not detail:
            print("   Could not get definition details", flush=True)
            continue

        repo = detail.get("repository", {}) or {}
        repo_name = repo.get("name", "")
        repo_type = repo.get("type", "")
        default_branch = repo.get("defaultBranch", "")

        process = detail.get("process", {}) or {}
        yaml_path = process.get("yamlFilename", "")
        pipeline_type = "YAML" if yaml_path else "Classic/Unknown"

        full_text = json.dumps(detail).lower()
        matched_count = 0

        for sc_name, sc in sc_by_name.items():
            sc_id = str(sc.get("id", "")).lower()
            sc_name_l = sc_name.lower()

            matched = False
            method = ""

            if sc_name_l and sc_name_l in full_text:
                matched = True
                method = "DefinitionJSON_NAME"
            elif sc_id and sc_id in full_text:
                matched = True
                method = "DefinitionJSON_ID"

            if matched:
                matched_count += 1

                raw_map_rows.append({
                    "Project": project_name,
                    "PipelineId": def_id,
                    "PipelineName": def_name,
                    "PipelineType": pipeline_type,
                    "Repository": repo_name,
                    "RepoType": repo_type,
                    "DefaultBranch": default_branch,
                    "YamlPath": yaml_path,
                    "ServiceConnectionName": sc_name,
                    "ServiceConnectionId": sc.get("id", ""),
                    "ServiceConnectionType": sc.get("type", ""),
                    "IsShared": sc.get("isShared", False),
                    "DetectionMethod": method
                })

                sc_to_pipelines.setdefault(sc_name, set()).add(def_name)
                pipeline_to_scs.setdefault(def_name, set()).add(sc_name)

        print(f"   Matched {matched_count} service connection(s)", flush=True)

    # 4. Execution history
    print("[4/4] Scanning execution history...", flush=True)
    last_used_by_sc = {}
    times_used_by_sc = {}

    for sc in service_connections:
        sc_name = sc.get("name", "")
        sc_id = sc.get("id", "")
        hist_url = f"{base_url}/{project_name}/_apis/serviceendpoint/{sc_id}/executionhistory?top=100&api-version=7.0"
        hist = ado_get(hist_url, headers)

        if hist and hist.get("count", 0) > 0:
            items = hist.get("value", [])
            times_used_by_sc[sc_name] = len(items)

            latest = ""
            for item in items:
                finish = (item.get("data") or {}).get("finishTime", "")
                if finish and finish > latest:
                    latest = finish[:10]
            last_used_by_sc[sc_name] = latest if latest else "Unknown"
        else:
            times_used_by_sc[sc_name] = 0
            last_used_by_sc[sc_name] = "Never"

    # Deduplicate raw mapping
    dedup = {}
    for row in raw_map_rows:
        key = (
            row["PipelineId"],
            row["PipelineName"],
            row["ServiceConnectionName"],
            row["DetectionMethod"]
        )
        dedup[key] = row
    raw_map_rows = list(dedup.values())

    # Audit rows
    audit_rows = []
    found_sc_names = set(sc_by_name.keys())
    missing_known = [x for x in KNOWN_CONNECTIONS if x not in found_sc_names]

    for sc in service_connections:
        sc_name = sc.get("name", "")
        pipelines_using = sorted(list(sc_to_pipelines.get(sc_name, set())))
        pipeline_count = len(pipelines_using)
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
            "TimesUsed_Last100": times_used_by_sc.get(sc_name, 0),
            "LastUsedDate": last_used_by_sc.get(sc_name, "Never"),
            "PipelineCount": pipeline_count,
            "PipelinesUsing": " | ".join(pipelines_using),
            "AuthScheme": (sc.get("authorization") or {}).get("scheme", ""),
            "CreatedBy": (sc.get("createdBy") or {}).get("displayName", ""),
            "Description": sc.get("description", ""),
            "Recommendation": classify(is_dss, pipeline_count, is_known)
        })

    for missing in missing_known:
        audit_rows.append({
            "Project": project_name,
            "ConnectionName": missing,
            "ConnectionID": "",
            "Type": "",
            "IsShared": "",
            "IsDssStandard": missing.startswith(DSS_PREFIX),
            "IsReady": "",
            "TimesUsed_Last100": 0,
            "LastUsedDate": "Not found",
            "PipelineCount": 0,
            "PipelinesUsing": "",
            "AuthScheme": "",
            "CreatedBy": "",
            "Description": "Known from ticket but not found in project service connections",
            "Recommendation": "NOT FOUND IN PROJECT"
        })

    # SC -> Pipelines summary
    sc_to_pipe_rows = []
    for sc in sorted(sc_by_name.keys(), key=lambda x: x.lower()):
        sc_obj = sc_by_name[sc]
        pipes = sorted(list(sc_to_pipelines.get(sc, set())))
        sc_to_pipe_rows.append({
            "Project": project_name,
            "ServiceConnectionName": sc,
            "ServiceConnectionId": sc_obj.get("id", ""),
            "Type": sc_obj.get("type", ""),
            "IsShared": sc_obj.get("isShared", False),
            "PipelineCount": len(pipes),
            "PipelinesUsing": " | ".join(pipes)
        })

    # Pipeline -> SC summary
    pipe_to_sc_rows = []
    for bd in sorted(build_defs, key=lambda x: x.get("name", "").lower()):
        def_name = bd.get("name", "")
        def_id = bd.get("id", "")
        scs = sorted(list(pipeline_to_scs.get(def_name, set())))
        pipe_to_sc_rows.append({
            "Project": project_name,
            "PipelineId": def_id,
            "PipelineName": def_name,
            "ServiceConnectionCount": len(scs),
            "ServiceConnectionsUsed": " | ".join(scs)
        })

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

    with open(raw_map_csv, "w", newline="", encoding="utf-8") as f:
        if raw_map_rows:
            writer = csv.DictWriter(f, fieldnames=list(raw_map_rows[0].keys()))
            writer.writeheader()
            writer.writerows(sorted(
                raw_map_rows,
                key=lambda x: (
                    x["ServiceConnectionName"].lower(),
                    x["PipelineName"].lower()
                )
            ))
        else:
            writer = csv.writer(f)
            writer.writerow([
                "Project", "PipelineId", "PipelineName", "PipelineType", "Repository",
                "RepoType", "DefaultBranch", "YamlPath", "ServiceConnectionName",
                "ServiceConnectionId", "ServiceConnectionType", "IsShared", "DetectionMethod"
            ])

    print("\nDone.", flush=True)
    print(f"Audit CSV                  : {audit_csv}", flush=True)
    print(f"SC -> Pipelines CSV        : {sc_to_pipe_csv}", flush=True)
    print(f"Pipeline -> SC CSV         : {pipe_to_sc_csv}", flush=True)
    print(f"Raw Mapping CSV            : {raw_map_csv}", flush=True)

    target = "dss_devops_sc_sonarqube"
    if target in sc_to_pipelines:
        print(f"\nExample: {target}", flush=True)
        print(f"  Pipelines: {' | '.join(sorted(sc_to_pipelines[target]))}", flush=True)
    else:
        print(f"\nExample: {target} -> no pipelines found in definition scan", flush=True)

if __name__ == "__main__":
    main()
