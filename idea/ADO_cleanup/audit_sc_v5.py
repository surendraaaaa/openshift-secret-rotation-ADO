#!/usr/bin/env python3
"""
GIC_63623 - ADO Service Connection Audit + Pipeline Mapping
Final version:
- Works for YAML and Classic pipelines
- Uses execution history as primary source
- Extracts pipeline names from multiple possible fields
- Falls back to recent builds and definition scan
- Outputs one row per service connection with all pipelines using it
- Outputs one row per pipeline with all service connections used in it
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

def extract_pipeline_names_from_history_item(item):
    names = set()

    direct_pipeline = item.get("pipeline")
    if isinstance(direct_pipeline, dict):
        for key in ["name", "definitionName", "pipelineName"]:
            v = direct_pipeline.get(key)
            if isinstance(v, str) and v.strip():
                names.add(v.strip())

    data = item.get("data")
    if isinstance(data, dict):
        for key in [
            "definitionName", "pipelineName", "buildDefinitionName",
            "releaseDefinitionName", "planName"
        ]:
            v = data.get(key)
            if isinstance(v, str) and v.strip():
                names.add(v.strip())

        nested_definition = data.get("definition")
        if isinstance(nested_definition, dict):
            for key in ["name", "definitionName"]:
                v = nested_definition.get(key)
                if isinstance(v, str) and v.strip():
                    names.add(v.strip())

        nested_pipeline = data.get("pipeline")
        if isinstance(nested_pipeline, dict):
            for key in ["name", "definitionName", "pipelineName"]:
                v = nested_pipeline.get(key)
                if isinstance(v, str) and v.strip():
                    names.add(v.strip())

    owner = item.get("owner")
    if isinstance(owner, dict):
        for key in ["name", "definitionName"]:
            v = owner.get(key)
            if isinstance(v, str) and v.strip():
                names.add(v.strip())

    resource = item.get("resource")
    if isinstance(resource, dict):
        for key in ["name", "definitionName"]:
            v = resource.get(key)
            if isinstance(v, str) and v.strip():
                names.add(v.strip())

    return sorted(names)

def detect_service_connection_refs(obj, sc_names_lower, sc_ids_lower, found_names, found_ids):
    if isinstance(obj, dict):
        for _, v in obj.items():
            detect_service_connection_refs(v, sc_names_lower, sc_ids_lower, found_names, found_ids)
    elif isinstance(obj, list):
        for item in obj:
            detect_service_connection_refs(item, sc_names_lower, sc_ids_lower, found_names, found_ids)
    elif isinstance(obj, str):
        text = obj.lower()
        for name in sc_names_lower:
            if name and name in text:
                found_names.add(name)
        for sid in sc_ids_lower:
            if sid and sid in text:
                found_ids.add(sid)

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
    print("[1/5] Fetching service connections...", flush=True)
    sc_url = f"{base_url}/{project_name}/_apis/serviceendpoint/endpoints?includeDetails=true&api-version=7.1"
    sc_data = ado_get(sc_url, headers)
    if not sc_data:
        print("ERROR: Failed to retrieve service connections.", flush=True)
        sys.exit(1)

    service_connections = sc_data.get("value", [])
    print(f"  Found {len(service_connections)} service connections.", flush=True)

    sc_by_name = {}
    sc_by_id = {}
    for sc in service_connections:
        sc_name = sc.get("name", "").strip()
        sc_id = str(sc.get("id", "")).strip()
        if sc_name:
            sc_by_name[sc_name] = sc
        if sc_id:
            sc_by_id[sc_id.lower()] = sc

    sc_names_lower_map = {name.lower(): name for name in sc_by_name.keys()}
    sc_ids_lower_map = {sid.lower(): sid for sid in sc_by_id.keys()}

    # 2. Build definitions
    print("[2/5] Fetching build definitions...", flush=True)
    defs_url = f"{base_url}/{project_name}/_apis/build/definitions?api-version=7.1&$top=500"
    defs_data = ado_get(defs_url, headers)
    if not defs_data:
        print("ERROR: Failed to retrieve build definitions.", flush=True)
        sys.exit(1)

    build_defs = defs_data.get("value", [])
    print(f"  Found {len(build_defs)} build definitions.", flush=True)

    build_defs_by_id = {}
    build_name_by_id = {}
    for bd in build_defs:
        def_id = str(bd.get("id", "")).strip()
        def_name = bd.get("name", "").strip()
        if def_id:
            build_defs_by_id[def_id] = bd
            build_name_by_id[def_id] = def_name

    sc_to_pipelines = {name: set() for name in sc_by_name.keys()}
    pipeline_to_scs = {}
    times_used_by_sc = {}
    last_used_by_sc = {}
    raw_evidence_rows = []

    # 3. Execution history (primary)
    print("[3/5] Reading service connection execution history...", flush=True)
    for sc in service_connections:
        sc_name = sc.get("name", "").strip()
        sc_id = str(sc.get("id", "")).strip()

        hist_url = f"{base_url}/{project_name}/_apis/serviceendpoint/{sc_id}/executionhistory?top=500&api-version=7.0"
        hist = ado_get(hist_url, headers)

        if hist and hist.get("count", 0) > 0:
            items = hist.get("value", [])
            times_used_by_sc[sc_name] = len(items)

            latest = ""
            extracted_pipelines = set()

            for item in items:
                finish = safe_get(item, "data", "finishTime")
                if isinstance(finish, str) and finish and finish > latest:
                    latest = finish

                names = extract_pipeline_names_from_history_item(item)
                for n in names:
                    extracted_pipelines.add(n)
                    raw_evidence_rows.append({
                        "Project": project_name,
                        "ServiceConnectionName": sc_name,
                        "ServiceConnectionId": sc_id,
                        "EvidenceType": "ExecutionHistory",
                        "PipelineName": n,
                        "BuildDefinitionId": safe_get(item, "data", "definitionId") or safe_get(item, "pipeline", "id") or "",
                        "Detail": ""
                    })

            if latest:
                last_used_by_sc[sc_name] = latest[:10]
            else:
                last_used_by_sc[sc_name] = "Unknown"

            sc_to_pipelines[sc_name].update(extracted_pipelines)

            print(f"  {sc_name}: runs={len(items)}, pipelines_found={len(extracted_pipelines)}, last={last_used_by_sc[sc_name]}", flush=True)
        else:
            times_used_by_sc[sc_name] = 0
            last_used_by_sc[sc_name] = "Never"

    # 4. Recent builds fallback
    print("[4/5] Cross-checking recent builds...", flush=True)
    builds_url = f"{base_url}/{project_name}/_apis/build/builds?api-version=7.1&$top=500"
    builds_data = ado_get(builds_url, headers)

    if builds_data and isinstance(builds_data, dict):
        builds = builds_data.get("value", [])
        for b in builds:
            build_id = str(b.get("id", "")).strip()
            build_def = b.get("definition") or {}
            pipeline_name = build_def.get("name", "").strip()

            if not build_id or not pipeline_name:
                continue

            timeline_url = f"{base_url}/{project_name}/_apis/build/builds/{build_id}/timeline?api-version=7.1"
            timeline = ado_get(timeline_url, headers)
            if not timeline or not isinstance(timeline, dict):
                continue

            records = timeline.get("records", [])
            text_blob = json.dumps(records).lower()

            for sc_name, sc_obj in sc_by_name.items():
                sc_id = str(sc_obj.get("id", "")).lower()
                sc_name_l = sc_name.lower()

                if (sc_name_l and sc_name_l in text_blob) or (sc_id and sc_id in text_blob):
                    sc_to_pipelines[sc_name].add(pipeline_name)
                    raw_evidence_rows.append({
                        "Project": project_name,
                        "ServiceConnectionName": sc_name,
                        "ServiceConnectionId": sc_obj.get("id", ""),
                        "EvidenceType": "BuildTimeline",
                        "PipelineName": pipeline_name,
                        "BuildDefinitionId": build_def.get("id", ""),
                        "Detail": build_id
                    })

    # 5. Definition scan fallback for YAML/classic
    print("[5/5] Scanning build definitions for references...", flush=True)
    for bd in build_defs:
        def_id = str(bd.get("id", "")).strip()
        def_name = bd.get("name", "").strip()

        detail_url = f"{base_url}/{project_name}/_apis/build/definitions/{def_id}?api-version=7.1"
        detail = ado_get(detail_url, headers)
        if not detail:
            continue

        found_names = set()
        found_ids = set()
        detect_service_connection_refs(
            detail,
            set(sc_names_lower_map.keys()),
            set(sc_ids_lower_map.keys()),
            found_names,
            found_ids
        )

        for name_l in found_names:
            real_name = sc_names_lower_map[name_l]
            sc_to_pipelines[real_name].add(def_name)
            raw_evidence_rows.append({
                "Project": project_name,
                "ServiceConnectionName": real_name,
                "ServiceConnectionId": sc_by_name[real_name].get("id", ""),
                "EvidenceType": "DefinitionNameMatch",
                "PipelineName": def_name,
                "BuildDefinitionId": def_id,
                "Detail": ""
            })

        for sid_l in found_ids:
            sid_real = sc_ids_lower_map[sid_l]
            sc_obj = sc_by_id.get(sid_real.lower())
            if sc_obj:
                real_name = sc_obj.get("name", "")
                sc_to_pipelines[real_name].add(def_name)
                raw_evidence_rows.append({
                    "Project": project_name,
                    "ServiceConnectionName": real_name,
                    "ServiceConnectionId": sc_obj.get("id", ""),
                    "EvidenceType": "DefinitionIdMatch",
                    "PipelineName": def_name,
                    "BuildDefinitionId": def_id,
                    "Detail": ""
                })

    # Reverse map
    for sc_name, pipe_set in sc_to_pipelines.items():
        for pipe in pipe_set:
            pipeline_to_scs.setdefault(pipe, set()).add(sc_name)

    # Audit rows
    audit_rows = []
    for sc in service_connections:
        sc_name = sc.get("name", "").strip()
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
        def_name = bd.get("name", "").strip()
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
            str(row["Detail"])
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
                "EvidenceType", "PipelineName", "BuildDefinitionId", "Detail"
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
