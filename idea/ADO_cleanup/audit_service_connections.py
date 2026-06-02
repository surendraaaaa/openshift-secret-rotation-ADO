#!/usr/bin/env python3
"""
GIC_63623 - ADO Service Connection Audit
Identifies which service connections are in use vs unused across ADO projects.
Exports results to CSV for backup/drive storage.

Requirements:
    pip install requests         # one-time install, no sudo needed
    pip3 install requests        # if using python3 explicitly

Usage:
    python3 audit_service_connections.py
    python3 audit_service_connections.py --org bmo-gic --project GIC_63623
"""

import argparse
import base64
import csv
import getpass
import json
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not found.")
    print("Install it with: pip3 install requests --user")
    sys.exit(1)

# -----------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------

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

# -----------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------

def get_headers(pat: str) -> dict:
    encoded = base64.b64encode(f":{pat}".encode("ascii")).decode("ascii")
    return {
        "Authorization": f"Basic {encoded}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def ado_get(url: str, headers: dict) -> dict | None:
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        print(f"  WARNING: HTTP {e.response.status_code} for {url}")
        return None
    except Exception as e:
        print(f"  WARNING: Request failed for {url} — {e}")
        return None

def classify(sc_name: str, times_used: int, is_dss: bool, is_known: bool) -> tuple[str, str]:
    if times_used == 0:
        usage = "UNUSED"
    elif times_used < 5:
        usage = "LOW_USAGE"
    else:
        usage = "IN_USE"

    if is_dss:
        rec = "KEEP - DSS Standard"
    elif usage == "IN_USE":
        rec = "REVIEW - Active non-standard; migrate pipelines to dss_ equivalent"
    elif usage == "LOW_USAGE":
        rec = "REVIEW - Low usage non-standard; migrate to dss_ equivalent"
    elif usage == "UNUSED" and is_known:
        rec = "CANDIDATE FOR REMOVAL - Unused (in known list)"
    else:
        rec = "CANDIDATE FOR REMOVAL - Unused & not in known list; investigate"

    return usage, rec

# -----------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="ADO Service Connection Audit - GIC_63623")
    parser.add_argument("--org",     help="ADO organization name (e.g. bmo-gic)")
    parser.add_argument("--project", help="Optional: limit scan to one project name", default="")
    parser.add_argument("--output",  help="Output CSV filename", default="")
    args = parser.parse_args()

    # Prompts if not passed as args
    org = args.org or input("Enter your ADO Organization name (e.g. bmo-gic): ").strip()
    pat = getpass.getpass("Enter your Personal Access Token (PAT): ")  # hidden input

    if not org or not pat:
        print("ERROR: Org name and PAT are required.")
        sys.exit(1)

    output_file = args.output or f"ServiceConnection_Audit_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    headers     = get_headers(pat)
    base_url    = f"https://dev.azure.com/{org}"
    api_ver     = "api-version=7.1"

    print(f"\n===== GIC_63623 - ADO Service Connection Audit =====")
    print(f"Organization : {org}")
    print(f"Started at   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ── STEP 1: Get projects ───────────────────────────────────────
    print("[1/4] Fetching projects...")
    projects_data = ado_get(f"{base_url}/_apis/projects?{api_ver}&$top=200", headers)

    if not projects_data:
        print("ERROR: Could not fetch projects. Check your org name and PAT permissions.")
        sys.exit(1)

    projects = projects_data.get("value", [])

    if args.project:
        projects = [p for p in projects if p["name"] == args.project]
        if not projects:
            print(f"ERROR: Project '{args.project}' not found in org '{org}'.")
            sys.exit(1)

    print(f"  Found {len(projects)} project(s) to audit.")

    # ── STEP 2: Service connections + usage history ────────────────
    print("\n[2/4] Fetching service connections and execution history...")
    all_results = []

    for project in projects:
        proj_name = project["name"]
        print(f"  -> Project: {proj_name}")

        sc_data = ado_get(
            f"{base_url}/{proj_name}/_apis/serviceendpoint/endpoints?includeDetails=true&{api_ver}",
            headers
        )
        if not sc_data:
            continue

        connections = sc_data.get("value", [])
        print(f"     Found {len(connections)} service connection(s)")

        for sc in connections:
            sc_name = sc.get("name", "")
            sc_id   = sc.get("id", "")

            # Get execution history - this is what tells us which pipelines USE this connection
            hist_data = ado_get(
                f"{base_url}/{proj_name}/_apis/serviceendpoint/{sc_id}/executionhistory?top=100&api-version=7.0",
                headers
            )

            last_used       = "Never"
            times_used      = 0
            pipelines_using = []

            if hist_data and hist_data.get("count", 0) > 0:
                hist_items = hist_data.get("value", [])
                times_used = len(hist_items)

                # Find most recent finish time
                finish_times = [
                    item.get("data", {}).get("finishTime")
                    for item in hist_items
                    if item.get("data", {}).get("finishTime")
                ]
                if finish_times:
                    latest = sorted(finish_times)[-1]
                    try:
                        last_used = latest[:10]  # Trim to YYYY-MM-DD
                    except Exception:
                        last_used = latest

                # Unique pipeline names
                seen = set()
                for item in hist_items:
                    pl = item.get("pipeline", {})
                    name = pl.get("name") if pl else None
                    if name and name not in seen:
                        pipelines_using.append(name)
                        seen.add(name)

            is_dss   = sc_name.startswith(DSS_PREFIX)
            is_known = sc_name in KNOWN_CONNECTIONS
            usage_status, recommendation = classify(sc_name, times_used, is_dss, is_known)

            auth     = sc.get("authorization", {})
            created  = sc.get("createdBy", {})

            all_results.append({
                "Project":            proj_name,
                "ConnectionName":     sc_name,
                "ConnectionID":       sc_id,
                "Type":               sc.get("type", ""),
                "IsShared":           sc.get("isShared", False),
                "IsDssStandard":      is_dss,
                "IsReady":            sc.get("isReady", False),
                "TimesUsed_Last100":  times_used,
                "LastUsedDate":       last_used,
                "UsageStatus":        usage_status,
                "PipelinesUsing":     " | ".join(pipelines_using),
                "AuthScheme":         auth.get("scheme", ""),
                "CreatedBy":          created.get("displayName", ""),
                "Description":        sc.get("description", ""),
                "Recommendation":     recommendation,
            })

    # ── STEP 3: Cross-reference known list ────────────────────────
    print("\n[3/4] Cross-referencing with known connection list...")
    found_names     = {r["ConnectionName"] for r in all_results}
    missing_from_ado = [c for c in KNOWN_CONNECTIONS if c not in found_names]

    if missing_from_ado:
        print("  WARNING: These known connections were NOT found in scanned projects:")
        for name in missing_from_ado:
            print(f"    - {name}")
        print("  They may exist in a different project or may already be deleted.")

    # ── STEP 4: Export to CSV ──────────────────────────────────────
    print(f"\n[4/4] Exporting results to CSV...")
    if all_results:
        fieldnames = list(all_results[0].keys())
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_results)
        print(f"  Saved to: {output_file}")
    else:
        print("  No results to export.")

    # ── SUMMARY ───────────────────────────────────────────────────
    in_use        = sum(1 for r in all_results if r["UsageStatus"] == "IN_USE")
    low_usage     = sum(1 for r in all_results if r["UsageStatus"] == "LOW_USAGE")
    unused        = sum(1 for r in all_results if r["UsageStatus"] == "UNUSED")
    dss_count     = sum(1 for r in all_results if r["IsDssStandard"])
    non_dss_unused= sum(1 for r in all_results if not r["IsDssStandard"] and r["UsageStatus"] == "UNUSED")

    print(f"\n===== SUMMARY =====")
    print(f"Total Connections Audited  : {len(all_results)}")
    print(f"  DSS Standard (dss_*)    : {dss_count}   <- Target standard; keep all")
    print(f"  IN_USE                  : {in_use}")
    print(f"  LOW_USAGE  (< 5 runs)   : {low_usage}")
    print(f"  UNUSED                  : {unused}")
    print(f"  Non-DSS and Unused      : {non_dss_unused}  <- Primary removal candidates")
    print(f"\nNext steps:")
    print(f"  1. Open {output_file} in Excel -> sort by 'Recommendation' column")
    print(f"  2. REVIEW rows -> confirm pipelines can switch to a dss_devops_* connection")
    print(f"  3. CANDIDATE FOR REMOVAL -> get team sign-off before deleting")
    print(f"  4. Save this CSV to the drive as backup (GIC_63623 / DSSDEVOPS-6200)")

if __name__ == "__main__":
    main()
