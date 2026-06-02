#!/usr/bin/env python3
"""
GIC_63623 - Accurate ADO Service Connection YAML Scanner
Goal:
- For each service connection, list pipelines where that SC is referenced in YAML
- Works best for YAML pipelines
- Also handles classic definitions only when they have YAML-like task/process data
- Avoids execution history and timeline false positives
"""

import argparse
import base64
import csv
import getpass
import json
import re
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
    "dss_devops_sc_artifactory", "dss_devops_sc_artifactory_platform",
    "dss_devops_sc_openshift_water", "dss_devops_sc_sonarqube",
    "GIC_63623_SonarQube", "github.com_sa-onboarding_bmogc-Belle_Isle",
    "Frog_gic", "Frog_gic_Saas", "jfrog-artifactory", "jfrog-connection",
    "jfrog-connection-publish", "Jfrog-gic", "SPLAT_Components_24757",
    "svc_bwa_dev01", "test_connection", "Testing-artifactory-token"
]

USAGE_KEYS = {
    "endpoint",
    "serviceconnection",
    "serviceconnectionname",
    "serviceendpoint",
    "serviceendpointid",
    "connectedservice",
    "connectedservicename",
    "connectedserviceid",
    "connectedservicearm",
    "connectedserviceazurerm",
    "azuresubscription",
    "sonarconnection",
    "containerregistry",
    "dockerregistryserviceconnection",
    "kubernetesserviceconnection",
    "artifactoryconnection",
    "jfrogserviceconnection",
    "source_artifactory_connection",
    "target_artifactory_connection",
    "connection",
    "repositoryendpoint",
    "externalendpoint",
    "nugetserviceconnection",
    "npmserviceconnection"
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

def normalize(value):
    if value is None:
        return ""
    return str(value).strip()

def canonical(value):
    s = normalize(value).lower()
    return re.sub(r"[^a-z0-9]", "", s)

def canon_match(a, b):
    return canonical(a) and canonical(a) == canonical(b)

def extract_yaml_from_definition(detail):
    config = detail.get("process", {}) or {}
    if isinstance(config, dict):
        yaml_file = config.get("yamlFilename") or config.get("yamlfilename") or ""
        if yaml_file:
            return yaml_file

    # fallback to repository + path if available
    repo = detail.get("repository", {}) or {}
    path = repo.get("defaultBranch", "") or ""
    return ""

def find_referenced_yaml(detail):
    # For classic definitions, try to locate YAML-like path if present.
    process = detail.get("process", {}) or {}
    if isinstance(process, dict):
        yaml_filename = process.get("yamlFilename")
        if yaml_filename:
            return yaml_filename
    return ""

def get_yaml_content(base_url, project_name, repo_id, yaml_path, headers, default_branch=""):
    if not repo_id or not yaml_path:
        return None

    encoded_path = quote(yaml_path, safe="/")
    versions = []

    if default_branch:
        versions.append(default_branch)

    versions += ["refs/heads/main", "refs/heads/master", "main", "master", ""]

    seen = set()
    versions = [v for v in versions if not (v in seen or seen.add(v))]

    for branch in versions:
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

        if isinstance(data, dict) and data.get("content"):
            return data["content"]

        if isinstance(data, str) and data.strip():
            return data

    return None

def line_based_yaml_match(yaml_text, sc_name, sc_id):
    """
    Look for exact SC name/id in lines where the key suggests service connection usage.
    """
    if not yaml_text:
        return []

    matches = []
    sc_name_l = normalize(sc_name).lower()
    sc_id_l = normalize(sc_id).lower()

    if not sc_name_l and not sc_id_l:
        return matches

    lines = yaml_text.splitlines()
    key_patterns = [
        "endpoint:", "serviceconnection:", "serviceConnection:",
        "sonarconnection:", "connectedservicename:", "connectedservice:",
        "source_artifactory_connection:", "target_artifactory_connection:",
        "dockerregistryserviceconnection:", "kubernetesserviceconnection:",
        "artifactoryconnection:", "jfrogserviceconnection:"
    ]

    for i, line in enumerate(lines, start=1):
        l = line.strip()
        low = l.lower()

        if not any(k.lower() in low for k in key_patterns):
            continue

        if sc_id_l and sc_id_l in low:
            matches.append((i, line.strip(), "ID"))
            continue

        if sc_name_l and canon_match(sc_name, line):
            matches.append((i, line.strip(), "NAME"))
            continue

        # also catch exact name if it appears in a quoted scalar on a relevant line
        if sc_name_l and sc_name_l in low:
            matches.append((i, line.strip(), "NAME_SUBSTRING"))
            continue

    return matches

def main():
    parser = argparse.ArgumentParser(description="ADO YAML Service Connection Usage Scanner")
    parser.add_argument("--org", required=False)
    parser.add_argument("--project", required=False)
    parser.add_argument("--output-prefix", required=False, default="")
    args = parser.parse_args()

    org = args.org or input("Enter your ADO Organization name: ").strip()
    project_name = args.project or input("Enter project name (e.g. GIC_63623): ").strip()

    print("Enter PAT: ", end="", flush=True)
    pat = getpass.getpass("")

    if not org or not project_name or not pat:
        print("ERROR: org, project, and PAT are required.")
        sys.exit(1)

    ts = datetime.now().strftime("%Y%m%d_%H%M")
    prefix = args.output_prefix or f"{project_name}_{ts}"

    sc_to_pipe_csv = f"{prefix}_service_connection_to_pipelines.csv"
    pipe_to_sc_csv = f"{prefix}_pipeline_to_service_connections.csv"
    raw_csv = f"{prefix}_raw_yaml_matches.csv"

    headers = get_headers(pat)
    base_url = f"https://dev.azure.com/{org}"

    print("\n[1/4] Fetching service connections...")
    sc_url = f"{base_url}/{project_name}/_apis/serviceendpoint/endpoints?includeDetails=true&api-version=7.1"
    sc_data = ado_get(sc_url, headers)
    if not sc_data:
        print("ERROR: Could not fetch service connections.")
        sys.exit(1)

    service_connections = sc_data.get("value", [])
    print(f"  Found {len(service_connections)} service connections.")

    sc_by_name = {}
    for sc in service_connections:
        name = normalize(sc.get("name"))
        if name:
            sc_by_name[name] = sc

    print("[2/4] Fetching build definitions...")
    defs_url = f"{base_url}/{project_name}/_apis/build/definitions?api-version=7.1&$top=500"
    defs_data = ado_get(defs_url, headers)
    if not defs_data:
        print("ERROR: Could not fetch build definitions.")
        sys.exit(1)

    build_defs = defs_data.get("value", [])
    print(f"  Found {len(build_defs)} build definitions.")

    sc_to_pipelines = {name: set() for name in sc_by_name}
    pipeline_to_scs = {}
    raw_rows = []

    print("[3/4] Reading YAML and matching service connections...")
    for i, bd in enumerate(build_defs, start=1):
        def_id = str(bd.get("id", "")).strip()
        def_name = normalize(bd.get("name"))
        repo = bd.get("repository", {}) or {}
        repo_id = normalize(repo.get("id"))
        repo_name = normalize(repo.get("name"))
        default_branch = normalize(repo.get("defaultBranch"))

        yaml_path = find_referenced_yaml(bd)
        if not yaml_path:
            continue

        yaml_text = get_yaml_content(base_url, project_name, repo_id, yaml_path, headers, default_branch)
        if not yaml_text:
            continue

        for sc_name, sc in sc_by_name.items():
            sc_id = normalize(sc.get("id"))
            matches = line_based_yaml_match(yaml_text, sc_name, sc_id)

            if matches:
                sc_to_pipelines[sc_name].add(def_name)
                pipeline_to_scs.setdefault(def_name, set()).add(sc_name)

                for line_no, line_text, match_type in matches:
                    raw_rows.append({
                        "Project": project_name,
                        "PipelineId": def_id,
                        "PipelineName": def_name,
                        "Repository": repo_name,
                        "YamlPath": yaml_path,
                        "ServiceConnectionName": sc_name,
                        "ServiceConnectionId": sc_id,
                        "MatchType": match_type,
                        "LineNumber": line_no,
                        "LineText": line_text
                    })

        print(f"  [{i}/{len(build_defs)}] {def_name}", flush=True)

    print("[4/4] Writing outputs...")

    sc_to_pipe_rows = []
    for sc_name in sorted(sc_by_name.keys(), key=lambda x: x.lower()):
        sc = sc_by_name[sc_name]
        pipes = sorted(sc_to_pipelines.get(sc_name, set()))
        sc_to_pipe_rows.append({
            "Project": project_name,
            "ServiceConnectionName": sc_name,
            "ServiceConnectionId": sc.get("id", ""),
            "Type": sc.get("type", ""),
            "IsShared": sc.get("isShared", False),
            "PipelineCount": len(pipes),
            "PipelinesUsing": " | ".join(pipes)
        })

    pipe_to_sc_rows = []
    for bd in sorted(build_defs, key=lambda x: normalize(x.get("name")).lower()):
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

    with open(sc_to_pipe_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(sc_to_pipe_rows[0].keys()))
        writer.writeheader()
        writer.writerows(sc_to_pipe_rows)

    with open(pipe_to_sc_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(pipe_to_sc_rows[0].keys()))
        writer.writeheader()
        writer.writerows(pipe_to_sc_rows)

    with open(raw_csv, "w", newline="", encoding="utf-8") as f:
        if raw_rows:
            writer = csv.DictWriter(f, fieldnames=list(raw_rows[0].keys()))
            writer.writeheader()
            writer.writerows(sorted(raw_rows, key=lambda x: (x["ServiceConnectionName"].lower(), x["PipelineName"].lower())))
        else:
            writer = csv.writer(f)
            writer.writerow(["Project", "PipelineId", "PipelineName", "Repository", "YamlPath", "ServiceConnectionName", "ServiceConnectionId", "MatchType", "LineNumber", "LineText"])

    print("\nDone.")
    print(f"SC -> Pipelines CSV : {sc_to_pipe_csv}")
    print(f"Pipeline -> SC CSV  : {pipe_to_sc_csv}")
    print(f"Raw YAML Match CSV  : {raw_csv}")

    for row in sorted(sc_to_pipe_rows, key=lambda x: (-x["PipelineCount"], x["ServiceConnectionName"].lower()))[:10]:
        print(f"{row['ServiceConnectionName']}: {row['PipelineCount']} pipeline(s)")

if __name__ == "__main__":
    main()
