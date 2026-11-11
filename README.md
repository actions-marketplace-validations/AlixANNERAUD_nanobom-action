# nanobom SBOM upload - vulnerability gate for GitHub Actions

[![Test](https://github.com/AlixANNERAUD/nanobom-action/actions/workflows/test.yml/badge.svg)](https://github.com/AlixANNERAUD/nanobom-action/actions/workflows/test.yml)
[![nanobom](https://img.shields.io/badge/nanobom-self--hosted%20SBOM%20tracker-blue)](https://github.com/AlixANNERAUD/nanobom)

Ship nothing known to be exploited. In one step, this action generates a CycloneDX SBOM of your
repository or container image (with Syft), uploads it to your
[nanobom](https://github.com/AlixANNERAUD/nanobom) instance, and brings the answer back into the
job:

- **a summary table** of the project's open vulnerabilities, known-exploited ones (CISA KEV)
  flagged, each linked to its page in nanobom;
- **annotations** on the findings that crossed your threshold and on forbidden licenses;
- **a failing job** with `fail-on: critical | high | medium | low | exploited | license`, or
  several at once such as `fail-on: high,license`;
- **outputs** (counts per severity, known-exploited count, license policy violations, project
  URL) for later steps.

```yaml
- uses: AlixANNERAUD/nanobom-action@v1
  with:
    url: ${{ vars.NANOBOM_URL }}
    token: ${{ secrets.NANOBOM_TOKEN }}
    organization: acme
    fail-on: high
```

Without an `sbom`, the action generates one with [Syft](https://github.com/anchore/syft) (through
[anchore/sbom-action](https://github.com/anchore/sbom-action)) from the checkout. The project
defaults to the repository's name and is created by its first upload.

## Setup

1. In nanobom, open the organization's settings and create an **upload token** (it is shown
   once). A token of the organization can create projects; a token of one project uploads to it
   only.
2. In the repository's settings, add the token as the secret `NANOBOM_TOKEN` and the instance's
   address as the variable `NANOBOM_URL`.
3. Add the step after the checkout (and after the build, if the SBOM comes from build output).

## Inputs

| Input | Default | |
| --- | --- | --- |
| `url` | required | Address of the nanobom instance |
| `token` | required | Upload token |
| `organization` | required | Organization slug |
| `project` | repository name | Project slug |
| `sbom` | | Path of an existing CycloneDX JSON SBOM; without it, one is generated |
| `scan-path` | `.` | Directory Syft scans when no `sbom` is given |
| `scan-image` | | Container image Syft scans instead of `scan-path` |
| `version` | | Version of the project to upload to, such as `release/2.4` or `2.4`; created by its first upload; empty for the unnamed version |
| `latest` | | `true` or `false`: whether the version becomes the project's latest; empty makes a new version the latest and leaves an existing one alone |
| `fail-on` | | Fail when open findings are at or above `critical`, `high`, `medium` or `low`, when one is known `exploited` (CISA KEV), or when a component's license is forbidden by the organization's `license` policy; several separated by commas (`high,license`); implies `wait` |
| `wait` | `true` | Wait for the evaluation and report it |
| `source-commit` | the workflow's commit | Commit shown in the project's upload history |
| `image-tag` | the Git tag, if any | Image tag shown in the upload history |
| `summary` | `true` | Write the evaluation to the job summary |

## Outputs

| Output | |
| --- | --- |
| `http-status` | HTTP status of the upload |
| `project-url` | The project's page in nanobom |
| `evaluation-status` | `succeeded`, `failed` or `timed_out`; empty without `wait` |
| `critical`, `high`, `medium`, `low` | Open findings of the project by severity |
| `known-exploited` | Open findings known to be exploited |
| `forbidden-licenses`, `warned-licenses` | Components whose license the organization's policy forbids or warns about; empty without a policy |
| `sbom` | Path of the uploaded SBOM |

The job fails when the upload is refused (token, project, size, invalid document), when
`fail-on` is crossed (one annotation per finding and per forbidden license, up to ten each), or
when `fail-on` names a severity or `exploited` and the evaluation did not complete (OSV
unreachable, or longer than the server's `NANOBOM_UPLOAD_WAIT_SECONDS`). `wait`, `fail-on` and
the evaluation need nanobom with the upload gate; older versions accept the upload and report no
evaluation. Lists and `license` need nanobom with license policies.

## Examples

A container image, released by tag:

```yaml
on:
  push:
    tags: ["v*"]

jobs:
  sbom:
    runs-on: ubuntu-24.04
    steps:
      - uses: AlixANNERAUD/nanobom-action@v1
        with:
          url: ${{ vars.NANOBOM_URL }}
          token: ${{ secrets.NANOBOM_TOKEN }}
          organization: acme
          project: web
          scan-image: ghcr.io/acme/web:${{ github.ref_name }}
          fail-on: exploited
```

A main branch and maintenance branches, each in its own version of the project, with `main`
kept as the latest ([versions](https://alixanneraud.github.io/nanobom/how-to/track-versions.html)):

```yaml
on:
  push:
    branches: [main, "release/**"]

jobs:
  sbom:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7.0.1
      - uses: AlixANNERAUD/nanobom-action@v1
        with:
          url: ${{ vars.NANOBOM_URL }}
          token: ${{ secrets.NANOBOM_TOKEN }}
          organization: acme
          version: ${{ github.ref_name }}
          latest: ${{ github.ref_name == 'main' }}
          fail-on: high
```

Run it on long-lived branches only: on pull request branches, `ref_name` would create a version
per branch.

An SBOM from the build, with a later step using the outputs:

```yaml
- run: cargo cyclonedx --format json --override-filename sbom
- id: nanobom
  uses: AlixANNERAUD/nanobom-action@v1
  with:
    url: ${{ vars.NANOBOM_URL }}
    token: ${{ secrets.NANOBOM_TOKEN }}
    organization: acme
    sbom: sbom.json
- if: steps.nanobom.outputs.known-exploited != '0'
  run: echo "Known exploited vulnerabilities: ${{ steps.nanobom.outputs.project-url }}"
```

Reverse proxies in front of nanobom must allow the wait: raise their read timeout (nginx's
`proxy_read_timeout` is 60 s by default) above `NANOBOM_UPLOAD_WAIT_SECONDS`, or set
`wait: false` when no `fail-on` is needed.

## Development

`tests/run.sh` runs the upload script against a mock of nanobom's API (needs bash, curl, jq and
python3). CI also runs the action itself against the mock, and against nanobom built from its
main branch.

Releases are tagged `vX.Y.Z`, and the major tag `vX` is moved to the latest of its series.

## License

[Apache-2.0](LICENSE).
