#!/usr/bin/env bash
set -euo pipefail

CLUSTER=""
CSV=""
DRY_RUN="false"
ONLY_ENV_CONSUMERS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster) CLUSTER="$2"; shift 2 ;;
    --csv) CSV="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift 1 ;;
    --only-env-consumers) ONLY_ENV_CONSUMERS="true"; shift 1 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$CLUSTER" ]] || { echo "--cluster is required" >&2; exit 1; }
[[ -f "$CSV" ]] || { echo "CSV not found: $CSV" >&2; exit 1; }

tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

awk -F, -v cluster="\"$CLUSTER\"" -v only_env="$ONLY_ENV_CONSUMERS" '
  NR == 1 { next }
  $1 == cluster {
    usage = $6
    gsub(/"/, "", usage)
    if (only_env == "true") {
      if (usage !~ /^env\.secretKeyRef:/ && usage != "envFrom.secretRef") next
    }
    print $1","$2","$3","$4
  }
' "$CSV" | sort -u > "$tmpfile"

while IFS=, read -r cluster project kind workload; do
  cluster=$(echo "$cluster" | tr -d '"')
  project=$(echo "$project" | tr -d '"')
  kind=$(echo "$kind" | tr -d '"')
  workload=$(echo "$workload" | tr -d '"')

  case "$kind" in
    Deployment|StatefulSet|DaemonSet)
      if [[ "$DRY_RUN" == "true" ]]; then
        echo "DRY RUN: would restart ${kind,,}/$workload in $project on $CLUSTER" >&2
      else
        oc -n "$project" rollout restart "${kind,,}/$workload" >/dev/null || true
      fi
      ;;
    DeploymentConfig)
      if [[ "$DRY_RUN" == "true" ]]; then
        echo "DRY RUN: would rollout latest dc/$workload in $project on $CLUSTER" >&2
      else
        oc -n "$project" rollout latest "dc/$workload" >/dev/null || true
      fi
      ;;
    CronJob|Job)
      echo "Skipping automatic restart for $kind/$workload in $project on $CLUSTER" >&2
      ;;
  esac
done < "$tmpfile"