#!/usr/bin/env bash
set -euo pipefail

CLUSTER=""
CSV=""
SECRET_NAME="gitconfig"
SECRET_KEY="token"
NEW_VALUE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster) CLUSTER="$2"; shift 2 ;;
    --csv) CSV="$2"; shift 2 ;;
    --secret-name) SECRET_NAME="$2"; shift 2 ;;
    --secret-key) SECRET_KEY="$2"; shift 2 ;;
    --new-value) NEW_VALUE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$CLUSTER" ]] || { echo "--cluster is required" >&2; exit 1; }
[[ -f "$CSV" ]] || { echo "CSV not found: $CSV" >&2; exit 1; }
[[ -n "$NEW_VALUE" ]] || { echo "--new-value is required" >&2; exit 1; }

mapfile -t namespaces < <(tail -n +2 "$CSV" | awk -F, -v c="$CLUSTER" '$1 ~ c {gsub(/"/,"",$2); print $2}' | sort -u)

for ns in "${namespaces[@]}"; do
  echo "Updating secret $SECRET_NAME in $CLUSTER / $ns" >&2
  if oc -n "$ns" get secret "$SECRET_NAME" >/dev/null 2>&1; then
    oc -n "$ns" create secret generic "$SECRET_NAME" \
      --from-literal="$SECRET_KEY=$NEW_VALUE" \
      --dry-run=client -o yaml \
      | oc -n "$ns" apply -f - >/dev/null
  else
    echo "Secret $SECRET_NAME not found in namespace $ns on cluster $CLUSTER" >&2
  fi
done
