#!/usr/bin/env bash
set -euo pipefail

CLUSTER=""
CSV=""
SECRET_NAME="gitconfig"
SECRET_KEY="token"
NEW_VALUE=""
DRY_RUN="false"
BACKUP_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster) CLUSTER="$2"; shift 2 ;;
    --csv) CSV="$2"; shift 2 ;;
    --secret-name) SECRET_NAME="$2"; shift 2 ;;
    --secret-key) SECRET_KEY="$2"; shift 2 ;;
    --new-value) NEW_VALUE="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift 1 ;;
    --backup-dir) BACKUP_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$CLUSTER" ]] || { echo "--cluster is required" >&2; exit 1; }
[[ -f "$CSV" ]] || { echo "CSV not found: $CSV" >&2; exit 1; }
[[ -n "$NEW_VALUE" ]] || { echo "--new-value is required" >&2; exit 1; }

encoded_value=$(printf '%s' "$NEW_VALUE" | base64 | tr -d '\n')
mapfile -t namespaces < <(tail -n +2 "$CSV" | awk -F, -v c="$CLUSTER" '$1 == "\"" c "\"" {gsub(/"/,"",$2); print $2}' | sort -u)

[[ -n "$BACKUP_DIR" ]] && mkdir -p "$BACKUP_DIR"

for ns in "${namespaces[@]}"; do
  echo "Processing secret $SECRET_NAME in $CLUSTER / $ns" >&2

  if ! oc -n "$ns" get secret "$SECRET_NAME" >/dev/null 2>&1; then
    echo "Secret $SECRET_NAME not found in namespace $ns on cluster $CLUSTER" >&2
    continue
  fi

  if [[ -n "$BACKUP_DIR" ]]; then
    oc -n "$ns" get secret "$SECRET_NAME" -o yaml > "$BACKUP_DIR/${CLUSTER}-${ns}-${SECRET_NAME}.yaml"
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN: would patch secret/$SECRET_NAME key '$SECRET_KEY' in namespace $ns on cluster $CLUSTER" >&2
    continue
  fi

  oc -n "$ns" patch secret "$SECRET_NAME" \
    --type merge \
    -p "{\"data\":{\"$SECRET_KEY\":\"$encoded_value\"}}" >/dev/null
done