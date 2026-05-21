#!/usr/bin/env bash
set -euo pipefail

CLUSTER=""
CSV=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster) CLUSTER="$2"; shift 2 ;;
    --csv) CSV="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$CLUSTER" ]] || { echo "--cluster is required" >&2; exit 1; }
[[ -f "$CSV" ]] || { echo "CSV not found: $CSV" >&2; exit 1; }

while IFS=, read -r cluster project kind workload container usage; do
  [[ "$cluster" == 'cluster' ]] && continue
  cluster=$(echo "$cluster" | tr -d '"')
  project=$(echo "$project" | tr -d '"')
  kind=$(echo "$kind" | tr -d '"')
  workload=$(echo "$workload" | tr -d '"')

  [[ "$cluster" == "$CLUSTER" ]] || continue

  case "$kind" in
    Deployment|StatefulSet|DaemonSet)
      oc -n "$project" rollout restart "${kind,,}/$workload" >/dev/null || true
      ;;
    DeploymentConfig)
      oc -n "$project" rollout latest "dc/$workload" >/dev/null || true
      ;;
    CronJob|Job)
      echo "Skipping automatic restart for $kind/$workload in $project on $CLUSTER" >&2
      ;;
  esac

done < <(sort -u "$CSV")
