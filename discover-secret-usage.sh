#!/usr/bin/env bash
set -euo pipefail

CLUSTER=""
SECRET_NAME="gitconfig"
TARGET_PROJECTS=""
OUTPUT="secret-usage.csv"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster) CLUSTER="$2"; shift 2 ;;
    --secret-name) SECRET_NAME="$2"; shift 2 ;;
    --target-projects) TARGET_PROJECTS="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$CLUSTER" ]]; then
  echo "--cluster is required" >&2
  exit 1
fi

mapfile -t namespaces < <(
  if [[ -n "$TARGET_PROJECTS" ]]; then
    printf '%s' "$TARGET_PROJECTS" | tr ',' '\n' | sed '/^$/d'
  else
    oc get projects -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
  fi
)

workload_types=(deployment deploymentconfig statefulset daemonset job cronjob)

echo 'cluster,project,kind,workload,container_or_scope,usage' > "$OUTPUT"

scan_json() {
  local cluster="$1"
  local ns="$2"
  local kind="$3"
  local name="$4"
  local json="$5"

  echo "$json" | jq -r --arg cluster "$cluster" --arg ns "$ns" --arg kind "$kind" --arg name "$name" --arg secret "$SECRET_NAME" '
    def podspec:
      if .kind == "CronJob" then .spec.jobTemplate.spec.template.spec
      else .spec.template.spec
      end;
    (podspec) as $ps
    | ((($ps.containers // []) + ($ps.initContainers // []))[]?) as $c
    | $c.env[]?
    | select(.valueFrom.secretKeyRef.name? == $secret)
    | [$cluster, $ns, $kind, $name, ($c.name // "n/a"), ("env.secretKeyRef:" + .name)] | @csv
  ' >> "$OUTPUT"

  echo "$json" | jq -r --arg cluster "$cluster" --arg ns "$ns" --arg kind "$kind" --arg name "$name" --arg secret "$SECRET_NAME" '
    def podspec:
      if .kind == "CronJob" then .spec.jobTemplate.spec.template.spec
      else .spec.template.spec
      end;
    (podspec) as $ps
    | ((($ps.containers // []) + ($ps.initContainers // []))[]?) as $c
    | $c.envFrom[]?
    | select(.secretRef.name? == $secret)
    | [$cluster, $ns, $kind, $name, ($c.name // "n/a"), "envFrom.secretRef"] | @csv
  ' >> "$OUTPUT"

  echo "$json" | jq -r --arg cluster "$cluster" --arg ns "$ns" --arg kind "$kind" --arg name "$name" --arg secret "$SECRET_NAME" '
    def podspec:
      if .kind == "CronJob" then .spec.jobTemplate.spec.template.spec
      else .spec.template.spec
      end;
    (podspec) as $ps
    | $ps.volumes[]?
    | select(.secret.secretName? == $secret)
    | [$cluster, $ns, $kind, $name, "podspec", ("volume.secret:" + .name)] | @csv
  ' >> "$OUTPUT"

  echo "$json" | jq -r --arg cluster "$cluster" --arg ns "$ns" --arg kind "$kind" --arg name "$name" --arg secret "$SECRET_NAME" '
    def podspec:
      if .kind == "CronJob" then .spec.jobTemplate.spec.template.spec
      else .spec.template.spec
      end;
    (podspec) as $ps
    | $ps.imagePullSecrets[]?
    | select(.name? == $secret)
    | [$cluster, $ns, $kind, $name, "podspec", "imagePullSecret"] | @csv
  ' >> "$OUTPUT"
}

for ns in "${namespaces[@]}"; do
  for type in "${workload_types[@]}"; do
    oc -n "$ns" get "$type" -o json 2>/dev/null \
      | jq -c '.items[]?' \
      | while IFS= read -r obj; do
          name=$(echo "$obj" | jq -r '.metadata.name')
          kind=$(echo "$obj" | jq -r '.kind')
          scan_json "$CLUSTER" "$ns" "$kind" "$name" "$obj"
        done
  done
done

sort -u "$OUTPUT" -o "$OUTPUT"
{ echo 'cluster,project,kind,workload,container_or_scope,usage'; tail -n +2 "$OUTPUT"; } > "$OUTPUT.tmp"
mv "$OUTPUT.tmp" "$OUTPUT"
