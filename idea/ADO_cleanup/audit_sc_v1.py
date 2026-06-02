#!/usr/bin/env python3
"""
GIC_63623 - ADO Service Connection Audit + Pipeline Mapping
Python 3.9 compatible

What it does:
1. Lists all service connections in the target ADO project
2. Lists all YAML pipelines in the target project
3. Gets each pipeline's YAML path + repository
4. Downloads the YAML file content from the repo
5. Searches YAML for service connection names and IDs
6. Builds:
   - service_connection_audit.csv
   - service_connection_pipeline_map.csv
"""

import argparse
import base64
import csv
import getpass
import sys
from datetime import datetime
from urllib.parse import quote

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

def get_headers(pat):
    encoded = base64.b64encode(f":{pat}".encode("ascii")).decode("ascii")
    return {
        "Authorization": f"Basic {encoded}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

def ado_get(url, headers, expect_text=False):
    try:
        r = requests.get(url, headers=headers, timeout=60)
        r.raise_for_status()
        if expect_text:
            return r.text
        ctype = r.headers.get("Content-Type", "")
        if "application/json" in ctype:
            return r.json()
        return r.text
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response is not None else "UNKNOWN"
        print(f"  WARNING HTTP {code}: {url}")
        return None
    except Exception as e:
        print(f"  WARNING Request failed: {url} -> {e}")
        return None

def classify(is_dss, pipeline_count, is_known):
    if is_dss:
        return "KEEP - DSS Standard"
    if pipeline_count > 0:
        return "REVIEW - In use, non-standard"
    if is_known:
        return "CANDIDATE FOR REMOVAL - Not found in YAML scan"
    return "REVIEW - Unknown connection"

def extract_pipeline_yaml_info(pipeline_detail):
    config = pipeline_detail.get("configuration", {}) or {}
    repo = config.get("repository", {}) or {}

    return {
        "yaml_path": config.get("path", ""),
        "repo_id": repo.get("id", ""),
        "repo_name": repo.get("name", ""),
        "repo_type": repo.get("type", ""),
        "default_branch": repo.get("defaultBranch", "")
    }

def get_pipeline_yaml_content(base_url, project_name, repo_id, yaml_path, headers):
    if not repo_id or not yaml_path:
        return None, None

    encoded_path = quote(yaml_path, safe="/")
    branches_to_try = ["refs/heads/main", "refs/heads/master", "main", "master", ""]

    for branch in branches_to_try:
        if branch:
            url = (
                f"{base_url}/{project_name}/_apis/git/repositories/{repo_id}/items"
                f"?path={encoded_path}"
                f"&includeContent=true"
                f"&versionDescriptor.version={quote(branch, safe='')}"
                f"&versionDescriptor.versionType=branch"
                f"&api-version=7.1"
            )
        else:
            url = (
                f"{base_url}/{project_name}/_apis/git/repositories/{repo_id}/items"
                f"?path={encoded_path}"
                f"&includeContent=true"
                f"&api-version=7.1"
            )

        data = ado_get(url, headers)
        if not data:
            continue

        if isinstance(data, dict) and "content" in data and data["content"]:
            return data["content"], branch if branch else "default"

        if isinstance(data, str) and data.strip():
            return data, branch if branch else "default"

    return None, None

def main():
    parser = argparse.ArgumentParser(description="ADO Service Connection Audit + Pipeline Mapping")
    parser.add_argument("--org", required=False)
    parser.add_argument("--project", required=False)
    parser.add_argument("--output-prefix", required=False, default="")
    args = parser.parse_args()

    org = args.org or input("Enter your ADO Organization name: ").strip()
    project_name = args.project or input("Enter project name (e.g. GIC_63623): ").strip()
    pat = getpass.getpass("Enter PAT: ")

    if not org or not project_name or not pat:
        print("ERROR: org, project, and PAT are required.")
        sys.exit(1)

    ts = datetime.now().strftime("%Y%m%d_%H%M")
    prefix = args.output_prefix or f"{project_name}_{ts}"
    audit_csv = f"{prefix}_service_connection_audit.csv"
    map_csv = f"{prefix}_service_connection_pipeline_map.csv"

    headers = get_headers(pat)
    base_url = f"https://dev.azure.com/{org}"

    print(f"\nScanning project: {project_name}")

    # 1. Get service connections
    print("[1/4] Fetching service connections...")
    sc_url = f"{base_url}/{project_name}/_apis/serviceendpoint/endpoints?includeDetails=true&api-version=7.1"
    sc_data = ado_get(sc_url, headers)
    if not sc_data:
        print("ERROR: Failed to retrieve service connections.")
        sys.exit(1)

    service_connections = sc_data.get("value", [])
    print(f"  Found {len(service_connections)} service connections.")

    sc_by_name = {}
    for sc in service_connections:
        sc_name = sc.get("name", "")
        sc_by_name[sc_name] = sc

    # 2. Get pipelines
    print("[2/4] Fetching pipelines...")
    pipelines_url = f"{base_url}/{project_name}/_apis/pipelines?api-version=7.1"
    pipelines_data = ado_get(pipelines_url, headers)
    if not pipelines_data:
        print("ERROR: Failed to retrieve pipelines.")
        sys.exit(1)

    pipelines = pipelines_data.get("value", [])
    print(f"  Found {len(pipelines)} pipelines.")

    pipeline_map_rows = []
    usage_by_sc = {}

    # 3. Scan pipeline YAML files
    print("[3/4] Scanning pipeline YAML files for service connection references...")
    for pipe in pipelines:
        pipeline_id = pipe.get("id", "")
        pipeline_name = pipe.get("name", "")

        detail_url = f"{base_url}/{project_name}/_apis/pipelines/{pipeline_id}?api-version=7.1"
        detail = ado_get(detail_url, headers)
        if not detail:
            continue

        info = extract_pipeline_yaml_info(detail)
        yaml_path = info["yaml_path"]
        repo_id = info["repo_id"]
        repo_name = info["repo_name"]

        if not yaml_path or not repo_id:
            print(f"  Skipping pipeline '{pipeline_name}' - missing yaml path or repo id")
            continue

        yaml_content, branch_used = get_pipeline_yaml_content(
            base_url, project_name, repo_id, yaml_path, headers
        )

        if not yaml_content:
            print(f"  Could not read YAML for pipeline '{pipeline_name}' ({yaml_path})")
            continue

        yaml_lower = yaml_content.lower()

        for sc_name, sc in sc_by_name.items():
            sc_id = str(sc.get("id", "")).lower()
            sc_name_l = sc_name.lower()

            matched = False
            method = ""

            if sc_name_l and sc_name_l in yaml_lower:
                matched = True
                method = "YAML_NAME_MATCH"
            elif sc_id and sc_id in yaml_lower:
                matched = True
                method = "YAML_ID_MATCH"

            if matched:
                pipeline_map_rows.append({
                    "Project": project_name,
                    "PipelineId": pipeline_id,
                    "PipelineName": pipeline_name,
                    "Repository": repo_name,
                    "YamlPath": yaml_path,
                    "BranchUsed": branch_used,
                    "ServiceConnectionName": sc_name,
                    "ServiceConnectionId": sc.get("id", ""),
                    "ServiceConnectionType": sc.get("type", ""),
                    "IsShared": sc.get("isShared", False),
                    "DetectionMethod": method
                })

                usage_by_sc.setdefault(sc_name, set()).add(pipeline_name)

    # 4. Add execution history as supporting signal
    print("[4/4] Scanning execution history for additional evidence...")
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
                    latest = finish
            last_used_by_sc[sc_name] = latest[:10] if latest else "Unknown"
        else:
            times_used_by_sc[sc_name] = 0
            last_used_by_sc[sc_name] = "Never"

    # de-dup map rows
    dedup = {}
    for row in pipeline_map_rows:
        key = (
            row["PipelineId"],
            row["PipelineName"],
            row["YamlPath"],
            row["ServiceConnectionName"],
            row["DetectionMethod"]
        )
        dedup[key] = row
    pipeline_map_rows = list(dedup.values())

    # build audit rows
    audit_rows = []
    found_sc_names = set(sc_by_name.keys())
    missing_known = [x for x in KNOWN_CONNECTIONS if x not in found_sc_names]

    for sc in service_connections:
        sc_name = sc.get("name", "")
        pipelines_using = sorted(list(usage_by_sc.get(sc_name, set())))
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

    # write audit csv
    with open(audit_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(audit_rows[0].keys()))
        writer.writeheader()
        writer.writerows(sorted(audit_rows, key=lambda x: x["ConnectionName"].lower()))

    # write pipeline map csv
    if pipeline_map_rows:
        with open(map_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(pipeline_map_rows[0].keys()))
            writer.writeheader()
            writer.writerows(sorted(
                pipeline_map_rows,
                key=lambda x: (
                    x["ServiceConnectionName"].lower(),
                    x["PipelineName"].lower()
                )
            ))
    else:
        with open(map_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Project", "PipelineId", "PipelineName", "Repository", "YamlPath",
                "BranchUsed", "ServiceConnectionName", "ServiceConnectionId",
                "ServiceConnectionType", "IsShared", "DetectionMethod"
            ])

    print("\nDone.")
    print(f"Audit CSV       : {audit_csv}")
    print(f"Pipeline Map CSV: {map_csv}")

    target = "dss_devops_sc_sonarqube"
    match = [r for r in audit_rows if r["ConnectionName"] == target]
    if match:
        print(f"\nExample output for {target}:")
        print(f"  PipelineCount : {match[0]['PipelineCount']}")
        print(f"  PipelinesUsing: {match[0]['PipelinesUsing']}")
