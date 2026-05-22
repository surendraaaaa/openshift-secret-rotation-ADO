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

[[ -n "$CLUSTER" ]] || { echo "--cluster is required" >&2; exit 1; }

project_filter_regex=""
if [[ -n "$TARGET_PROJECTS" ]]; then
  project_filter_regex="^($(printf '%s' "$TARGET_PROJECTS" | tr ',' '|' | sed 's/[].[^$\\*+?{}|()]/\\&/g'))$"
fi

workload_types=(deployment deploymentconfig statefulset daemonset job cronjob)

echo 'cluster,project,kind,workload,container_or_scope,usage' > "$OUTPUT"

for type in "${workload_types[@]}"; do
  oc get "$type" -A -o json 2>/dev/null | jq -r \
    --arg cluster "$CLUSTER" \
    --arg secret "$SECRET_NAME" \
    --arg project_regex "$project_filter_regex" '
      def project_ok:
        if $project_regex == "" then true
        else (.metadata.namespace | test($project_regex))
        end;
      def podspec:
        if .kind == "CronJob" then .spec.jobTemplate.spec.template.spec
        else .spec.template.spec
        end;
      .items[]?
      | select(project_ok)
      | . as $obj
      | (podspec) as $ps
      | (
          [
            ((($ps.containers // []) + ($ps.initContainers // []))[]? as $c
              | $c.env[]?
              | select(.valueFrom.secretKeyRef.name? == $secret)
              | [$cluster, $obj.metadata.namespace, $obj.kind, $obj.metadata.name, ($c.name // "n/a"), ("env.secretKeyRef:" + .name)]),
            ((($ps.containers // []) + ($ps.initContainers // []))[]? as $c
              | $c.envFrom[]?
              | select(.secretRef.name? == $secret)
              | [$cluster, $obj.metadata.namespace, $obj.kind, $obj.metadata.name, ($c.name // "n/a"), "envFrom.secretRef"]),
            ($ps.volumes[]?
              | select(.secret.secretName? == $secret)
              | [$cluster, $obj.metadata.namespace, $obj.kind, $obj.metadata.name, "podspec", ("volume.secret:" + .name)]),
            ($ps.imagePullSecrets[]?
              | select(.name? == $secret)
              | [$cluster, $obj.metadata.namespace, $obj.kind, $obj.metadata.name, "podspec", "imagePullSecret"])
          ]
        )
      | .[]?
      | @csv
    ' >> "$OUTPUT"
done

sort -u "$OUTPUT" -o "$OUTPUT"
{ echo 'cluster,project,kind,workload,container_or_scope,usage'; tail -n +2 "$OUTPUT"; } > "$OUTPUT.tmp"
mv "$OUTPUT.tmp" "$OUTPUT"

# usage
# oc login <venus-api> --token=<venus-token>
# ./discover-secret-usage.sh --cluster venus --secret-name gitconfig --output venus-secret-usage.csv

# oc login <water-api> --token=<water-token>
# ./discover-secret-usage.sh --cluster water --secret-name gitconfig --output water-secret-usage.csv

# oc login <saturn-api> --token=<saturn-token>
# ./discover-secret-usage.sh --cluster saturn --secret-name gitconfig --output saturn-secret-usage.csv

# If you want only some projects
# ./discover-secret-usage.sh \
#   --cluster venus \
#   --secret-name gitconfig \
#   --target-projects proj1,proj2,proj3 \
#   --output venus-selected.csv
