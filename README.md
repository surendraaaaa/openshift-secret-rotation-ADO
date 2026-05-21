# Azure DevOps OpenShift secret rotation template

This package contains one Azure DevOps YAML pipeline and three Bash helper scripts to automate discovery, approval, secret update, and workload restart for an OpenShift secret such as `gitconfig`.

## Files

- `azure-pipelines-secret-rotation.yml`: main pipeline.
- `scripts/discover-secret-usage.sh`: scans target clusters/projects for workloads referencing the secret.
- `scripts/update-secret.sh`: updates the secret in matching namespaces.
- `scripts/restart-workloads.sh`: restarts supported workloads after secret update.

## Required pipeline variables

Create an Azure DevOps variable group such as `openshift-secret-rotation` and add:

- `OC_VENUS_API`
- `OC_VENUS_TOKEN`
- `OC_WATER_API`
- `OC_WATER_TOKEN`
- `OC_SATURN_API`
- `OC_SATURN_TOKEN`
- `GITCONFIG_NEW_VALUE`

Mark all tokens and `GITCONFIG_NEW_VALUE` as secret variables.

## Important note

`update-secret.sh` currently recreates the target secret with one literal key using:

- secret name: pipeline parameter `secretName`
- secret key: pipeline parameter `secretKey`
- secret value: secret variable `GITCONFIG_NEW_VALUE`

If your `gitconfig` secret contains multiple keys or stores a file like `.gitconfig`, adjust the update script so it patches only the intended key instead of replacing the whole secret payload.

## Suggested usage

1. Run with `mode: discover` to generate the report.
2. Review the `secret-usage-report` artifact.
3. Run with `mode: update` after approval.
