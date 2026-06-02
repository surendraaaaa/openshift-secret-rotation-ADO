#!/usr/bin/env python3
"""
GIC_63623 - ADO Service Connection Audit + Pipeline Mapping
Python 3.9 compatible
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
    "dss_devops_sc_artifactory", "dss_devops_s_artifactory_platform",
    "dss_devops_s_openshift_water", "dss_devops_sc_sonarqube",
    "GIC_63623_SonarQube", "github.com_sa-onboarding_bmogc-Belle_Isle",
    "Frog_gic", "Frog_gic_Saas", "jfrog-artifactory", "jfrog-connection",
    "jfrog-connection-publish", "Jfrog-gic", "SPLAT_Components_24757",
    "svc_bwa_dev01", "test_connection", "Testing-artifactory-token"
]

SERVICE_CONNECTION_INPUT_KEYS = {
    "connectedServiceName",
    "connectedServiceNameARM",
    "azureSubscription",
    "serviceConnection",
    "dockerRegistryServiceConnection",
    "containerRegistry",
    "SonarQube",
    "sonarQube",
    "artifactoryService",
    "jfrogServiceConnection",
    "kubernetesServiceConnection",
}

def get_headers(pat):
    encoded = base64.b64encode(f":{pat}".encode("ascii")).decode("ascii")
    return {
        "Authorization": f"Basic {encoded}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def ado_get(url, headers):
    try:
        r = requests.get(url, headers=headers, timeout=45)
        r.raise_for_status()
        if "application/json" in r.headers.get("Content-Type", ""):
            return r.json()
        return r.text
    except requests.exceptions.HTTPError as e:
        print(f"  WARNING HTTP {e.response.status_code}: {url}")
        return None
    except Exception as e:
        print(f"  WARNING Request failed: {url} -> {e}")
        return None

def classify(times_used, is_dss, is_known):
    if times_used == 0:
        usage = "UNUSED"
    elif times_used < 5:
        usage = "LOW_USAGE"
    else:
        usage = "IN_USE"

    if is_dss:
        rec = "KEEP - DSS Standard"
    elif usage == "IN_USE":
        rec = "REVIEW - Active non-standard; migrate to dss_ equivalent"
    elif usage == "LOW_USAGE":
        rec = "REVIEW - Low usage non-standard; migrate to dss_ equivalent"
    elif usage == "UNUSED" and is_known:
        rec = "CANDIDATE FOR REMOVAL - Unused (known list)"
    else:
        rec = "CANDIDATE FOR REMOVAL - Unused / investigate"
    return usage, rec

def deep_find_service_refs(obj, sc_names, found=None, current_key=None):
    if found is None:
        found = set()

    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k)
            if lk in SERVICE_CONNECTION_INPUT_KEYS and isinstance(v, str):
                if v in sc_names:
                    found.add(v)
            deep_find_service_refs(v, sc_names, found, lk)
    elif isinstance(obj, list):
        for item in obj:
            deep_find_service_refs(item, sc_names, found, current_key)
    elif isinstance(obj, str):
        if obj in sc_names:
            found.add(obj)

    return found

def scan_yaml_text_for_sc(yaml_text, sc_names):
    found = set()
    if not yaml_text:
        return found
    for sc in sc_names:
        if sc and sc in yaml_text:
            found.add(sc)
    return found

def main():
    parser = argparse.ArgumentParser(description="ADO Service Connection Audit")
    parser.add_argument("--org", required=False)
    parser.add_argument("--project", required=False, default="")
    parser.add_argument("--output-prefix", required=False, default="")
    args = parser.parse_args()

    org = args.org or input("Enter your ADO Organization name: ").strip()
    project_name = args.project or input("Enter project name (e.g. GIC_63623): ").strip()
    pat = getpass.getpass("Enter PAT: ")

    if not org or not project_name or not pat:
        print("ERROR: org, project, and PAT are required.")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    prefix = args.output_prefix or f"{project_name}_{timestamp}"
    audit_csv = f"{prefix}_service_connection_audit.csv"
    map_csv = f"{prefix}_service_connection_pipeline_map.csv"

    headers = get_headers(pat)
    base_url = f"https://dev.azure.com/{org}"
    release_base = f"https://vsrm.dev.azure.com/{org}"

    print(f"\nScanning project: {project_name}")

    # 1. Service connections
    sc_url = f"{base_url}/{project_name}/_apis/serviceendpoint/endpoints?includeDetails=true&api-version=7.1"
    sc_data = ado_get(sc_url, headers)
    if not sc_data:
        print("ERROR: failed to get service connections.")
        sys.exit(1)

    service_connections = sc_data.get("value", [])
    sc_by_id = {}
    sc_by_name = {}
    for sc in service_connections:
        sc_id = sc.get("id", "")
        sc_name = sc.get("name", "")
        sc_by_id[sc_id] = sc
        sc_by_name[sc_name] = sc

    sc_names = set(sc_by_name.keys())
    print(f"Found {len(sc_names)} service connections.")

    pipeline_map_rows = []
    usage_by_sc = {}

    # 2. Execution history
    print("Scanning service connection execution history...")
    for sc in service_connections:
        sc_id = sc.get("id", "")
        sc_name = sc.get("name", "")
        hist_url = f"{base_url}/{project_name}/_apis/serviceendpoint/{sc_id}/executionhistory?top=100&api-version=7.0"
        hist_data = ado_get(hist_url, headers)

        if hist_data and hist_data.get("count", 0) > 0:
            for item in hist_data.get("value", []):
                pipe = item.get("pipeline") or {}
                pipe_name = pipe.get("name", "")
                pipe_id = pipe.get("id", "")
                finish = item.get("data", {}).get("finishTime", "")
                usage_by_sc.setdefault(sc_name, {"times": 0, "pipelines": set(), "last_used": ""})
                usage_by_sc[sc_name]["times"] += 1
                if pipe_name:
                    usage_by_sc[sc_name]["pipelines"].add(pipe_name)
                    pipeline_map_rows.append({
                        "Project": project_name,
                        "PipelineType": "ExecutionHistory",
                        "PipelineId": pipe_id,
                        "PipelineName": pipe_name,
                        "ServiceConnection": sc_name,
                        "DetectionMethod": "ExecutionHistory",
                        "LastSeen": finish[:10] if finish else ""
                    })
                if finish and finish > usage_by_sc[sc_name]["last_used"]:
                    usage_by_sc[sc_name]["last_used"] = finish

    # 3. Build/YAML pipelines
    print("Scanning build/yaml pipelines...")
    build_defs_url = f"{base_url}/{project_name}/_apis/build/definitions?api-version=7.1&$top=500"
    build_defs = ado_get(build_defs_url, headers)
    if build_defs:
        for d in build_defs.get("value", []):
            def_id = d.get("id")
            def_name = d.get("name", "")

            detail_url = f"{base_url}/{project_name}/_apis/build/definitions/{def_id}?api-version=7.1"
            detail = ado_get(detail_url, headers)
            if detail:
                found_refs = deep_find_service_refs(detail, sc_names)
                for ref in found_refs:
                    pipeline_map_rows.append({
                        "Project": project_name,
                        "PipelineType": "BuildDefinition",
                        "PipelineId": def_id,
                        "PipelineName": def_name,
                        "ServiceConnection": ref,
                        "DetectionMethod": "DefinitionJSON",
                        "LastSeen": ""
                    })
                    usage_by_sc.setdefault(ref, {"times": 0, "pipelines": set(), "last_used": ""})
                    usage_by_sc[ref]["pipelines"].add(def_name)

            yaml_url = f"{base_url}/{project_name}/_apis/build/definitions/{def_id}/yaml?api-version=7.1"
            yaml_text = ado_get(yaml_url, headers)
            if isinstance(yaml_text, str):
                found_yaml_refs = scan_yaml_text_for_sc(yaml_text, sc_names)
                for ref in found_yaml_refs:
                    pipeline_map_rows.append({
                        "Project": project_name,
                        "PipelineType": "YamlPipeline",
                        "PipelineId": def_id,
                        "PipelineName": def_name,
                        "ServiceConnection": ref,
                        "DetectionMethod": "YAMLTextSearch",
                        "LastSeen": ""
                    })
                    usage_by_sc.setdefault(ref, {"times": 0, "pipelines": set(), "last_used": ""})
                    usage_by_sc[ref]["pipelines"].add(def_name)

    # 4. Classic release definitions
    print("Scanning classic release definitions...")
    rel_defs_url = f"{release_base}/{project_name}/_apis/release/definitions?api-version=7.1&$top=500"
    rel_defs = ado_get(rel_defs_url, headers)
    if rel_defs:
        for rd in rel_defs.get("value", []):
            rel_id = rd.get("id")
            rel_name = rd.get("name", "")
            rel_detail_url = f"{release_base}/{project_name}/_apis/release/definitions/{rel_id}?api-version=7.1"
            rel_detail = ado_get(rel_detail_url, headers)
            if rel_detail:
                found_refs = deep_find_service_refs(rel_detail, sc_names)
                rel_json = json.dumps(rel_detail)
                for scn in sc_names:
                    if scn in rel_json:
                        found_refs.add(scn)

                for ref in found_refs:
                    pipeline_map_rows.append({
                        "Project": project_name,
                        "PipelineType": "ClassicRelease",
                        "PipelineId": rel_id,
                        "PipelineName": rel_name,
                        "ServiceConnection": ref,
                        "DetectionMethod": "ReleaseDefinitionScan",
                        "LastSeen": ""
                    })
                    usage_by_sc.setdefault(ref, {"times": 0, "pipelines": set(), "last_used": ""})
                    usage_by_sc[ref]["pipelines"].add(rel_name)

    # de-duplicate pipeline map
    dedup = {}
    for row in pipeline_map_rows:
        key = (
            row["Project"], row["PipelineType"], str(row["PipelineId"]),
            row["PipelineName"], row["ServiceConnection"], row["DetectionMethod"]
        )
        dedup[key] = row
    pipeline_map_rows = list(dedup.values())

    # 5. Final audit rows
    audit_rows = []
    found_names = set(sc_by_name.keys())
    missing_known = [x for x in KNOWN_CONNECTIONS if x not in found_names]

    for sc in service_connections:
        sc_name = sc.get("name", "")
        stats = usage_by_sc.get(sc_name, {"times": 0, "pipelines": set(), "last_used": ""})
        is_dss = sc_name.startswith(DSS_PREFIX)
        is_known = sc_name in KNOWN_CONNECTIONS
        usage_status, recommendation = classify(stats["times"], is_dss, is_known)

        audit_rows.append({
            "Project": project_name,
            "ConnectionName": sc_name,
            "ConnectionID": sc.get("id", ""),
            "Type": sc.get("type", ""),
            "IsShared": sc.get("isShared", False),
            "IsDssStandard": is_dss,
            "IsReady": sc.get("isReady", False),
            "TimesUsed_Last100": stats["times"],
            "LastUsedDate": stats["last_used"][:10] if stats["last_used"] else "Never",
            "PipelinesUsing": " | ".join(sorted(stats["pipelines"])),
            "PipelineCount": len(stats["pipelines"]),
            "AuthScheme": (sc.get("authorization") or {}).get("scheme", ""),
            "CreatedBy": (sc.get("createdBy") or {}).get("displayName", ""),
            "Description": sc.get("description", ""),
            "Recommendation": recommendation
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
            "PipelinesUsing": "",
            "PipelineCount": 0,
            "AuthScheme": "",
            "CreatedBy": "",
            "Description": "Known from ticket but not found in project scan",
            "Recommendation": "NOT FOUND IN PROJECT"
        })

    # 6. Write CSVs
    with open(audit_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(audit_rows[0].keys()))
        writer.writeheader()
        writer.writerows(audit_rows)

    if pipeline_map_rows:
        with open(map_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(pipeline_map_rows[0].keys()))
            writer.writeheader()
            writer.writerows(sorted(
                pipeline_map_rows,
                key=lambda x: (x["ServiceConnection"], x["PipelineType"], x["PipelineName"])
            ))
    else:
        with open(map_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Project", "PipelineType", "PipelineId", "PipelineName", "ServiceConnection", "DetectionMethod", "LastSeen"])

    print("\nDone.")
    print(f"Audit CSV       : {audit_csv}")
    print(f"Pipeline Map CSV: {map_csv}")

if __name__ == "__main__":
    main()
