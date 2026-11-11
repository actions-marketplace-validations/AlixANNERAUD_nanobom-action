#!/usr/bin/env bash
# Uploads a CycloneDX SBOM to nanobom and reports the project's evaluation: outputs, a job
# summary and annotations. Configured through the NANOBOM_* variables set by action.yml.
set -euo pipefail

fail() {
  echo "::error title=nanobom::$1"
  exit 1
}

output() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "$1=$2" >> "$GITHUB_OUTPUT"
  fi
}

command -v jq > /dev/null || fail "jq is required"
command -v curl > /dev/null || fail "curl is required"

url="${NANOBOM_URL:?the url input is required}"
url="${url%/}"
token="${NANOBOM_TOKEN:?the token input is required}"
organization="${NANOBOM_ORGANIZATION:?the organization input is required}"
project="${NANOBOM_PROJECT:?the project input is required}"
sbom="${NANOBOM_SBOM:?no SBOM to upload}"
fail_on="$(printf '%s' "${NANOBOM_FAIL_ON:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
wait="${NANOBOM_WAIT:-true}"
version="${NANOBOM_VERSION:-}"
latest="$(printf '%s' "${NANOBOM_LATEST:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"

[[ -f "$sbom" ]] || fail "SBOM not found: $sbom"
case "$wait" in
  true | false) ;;
  *) fail "wait must be true or false, not '$wait'" ;;
esac
case "$latest" in
  "" | true | false) ;;
  *) fail "latest must be true or false, not '${NANOBOM_LATEST:-}'" ;;
esac
output sbom "$sbom"

# nanobom lower-cases slugs; the project URL is built the same way.
project_slug="$(printf '%s' "$project" | tr '[:upper:]' '[:lower:]')"
project_url="$url/organizations/$organization/projects/$project_slug"
output project-url "$project_url"

query="$(
  jq --raw-output --null-input \
    --arg source_commit "${NANOBOM_SOURCE_COMMIT:-}" \
    --arg image_tag "${NANOBOM_IMAGE_TAG:-}" \
    --arg version "$version" \
    --arg latest "$latest" \
    --arg fail_on "$fail_on" \
    --arg wait "$wait" \
    '[
      {key: "source_commit", value: $source_commit},
      {key: "image_tag", value: $image_tag},
      {key: "version", value: $version},
      {key: "latest", value: $latest},
      {key: "fail_on", value: $fail_on},
      {key: "wait", value: (if $wait == "true" and $fail_on == "" then "true" else "" end)}
    ]
    | map(select(.value != "") | "\(.key)=\(.value | @uri)")
    | join("&")'
)"
endpoint="$url/api/organizations/$(jq --raw-output --null-input --arg value "$organization" '$value | @uri')/projects/$(jq --raw-output --null-input --arg value "$project" '$value | @uri')/sbom"
[[ -n "$query" ]] && endpoint="$endpoint?$query"

response="$(mktemp)"
trap 'rm -f "$response"' EXIT
# The server waits up to NANOBOM_UPLOAD_WAIT_SECONDS (300 by default) for the evaluation.
if ! status="$(
  curl --silent --show-error --request PUT \
    --header "Authorization: Bearer $token" \
    --header "Content-Type: application/json" \
    --data-binary "@$sbom" \
    --output "$response" --write-out '%{http_code}' \
    --max-time 600 --retry 2 --retry-connrefused \
    "$endpoint"
)"; then
  fail "could not reach $url"
fi
output http-status "$status"

body_is_json=true
jq empty "$response" 2> /dev/null || body_is_json=false
field() {
  if $body_is_json; then jq --raw-output "$1 // empty" "$response"; fi
}
error="$(field '.error')"

case "$status" in
  200 | 201 | 409 | 503) ;;
  401) fail "the upload token was refused (401): ${error:-check the token input}" ;;
  403) fail "this token cannot upload to $organization/$project (403): $error" ;;
  404) fail "unknown organization or project $organization/$project (404): $error" ;;
  413) fail "the SBOM is larger than the server accepts (413)" ;;
  422) fail "nanobom refused the request (422): $error" ;;
  *) fail "unexpected answer from nanobom (HTTP $status): ${error:-$(head -c 500 "$response")}" ;;
esac
$body_is_json || fail "nanobom answered HTTP $status without a JSON body"

skipped="$(field '.components_without_purl')"
if [[ -n "$skipped" && "$skipped" != 0 ]]; then
  echo "::warning title=nanobom::$skipped components have no package URL, so OSV cannot check them; see the generator's settings"
fi

evaluation_status="$(field '.evaluation.status')"
output evaluation-status "$evaluation_status"
for level in critical high medium low; do
  output "$level" "$(field ".evaluation.open.$level")"
done
output known-exploited "$(field '.evaluation.known_exploited')"
output forbidden-licenses "$(field '.evaluation.licenses.forbidden')"
output warned-licenses "$(field '.evaluation.licenses.warned')"

if [[ "${NANOBOM_SUMMARY:-true}" == true && -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### nanobom: [$organization/$project_slug]($project_url)${version:+, version \`$version\`}"
    echo
    components="$(field '.component_count')"
    echo "Uploaded $components component$([[ "$components" == 1 ]] || echo s) (HTTP $status)."
    if [[ -n "$evaluation_status" ]]; then
      echo
      jq --raw-output '
        .evaluation as $e
        | "Evaluation: **\($e.status)**\n",
          "| Critical | High | Medium | Low | Unknown | Known exploited |",
          "| ---: | ---: | ---: | ---: | ---: | ---: |",
          "| \($e.open.critical) | \($e.open.high) | \($e.open.medium) | \($e.open.low) | \($e.open.unknown) | \($e.known_exploited) |",
          (if ($e.findings | length) > 0 then
            "\n| Vulnerability | Component | Severity | Known exploited |",
            "| --- | --- | --- | --- |",
            ($e.findings[:25][]
              | "| [\(.vulnerability)](\(.url)) | `\(.component)` | \(.severity) | \(if .known_exploited then "yes" else "" end) |"),
            (if ($e.findings | length) > 25 then "\nShowing 25 of \($e.findings | length) listed findings." else empty end)
          else "\nNo open findings." end),
          (if $e.licenses then
            "\nLicense policy: **\($e.licenses.forbidden)** forbidden, **\($e.licenses.warned)** warned.",
            (if ($e.licenses.violations | length) > 0 then
              "\n| Component | License | Verdict |",
              "| --- | --- | --- |",
              ($e.licenses.violations[:25][]
                | "| `\(.component)` | `\(.license // "unknown")` | \(.verdict) |")
            else empty end)
          else empty end)
      ' "$response"
    fi
    if [[ -n "$error" ]]; then
      echo
      echo "**$error**"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

case "$status" in
  409)
    # At most 10 annotations for the findings that crossed a threshold, and 10 for the forbidden
    # licenses. `fail_on` is a comma-separated list, for example `high,license`.
    jq --raw-output --arg fail_on "$fail_on" '
      ["critical", "high", "medium", "low"] as $levels
      | ($fail_on | split(",")) as $items
      | ([$items[] | . as $item | $levels | index($item) | select(. != null)] | max) as $threshold
      | ($items | index("exploited") != null) as $exploited
      | ([.evaluation.findings[]?
          | select((.known_exploited and $exploited)
                   or ($threshold != null
                       and (.severity as $severity | ($levels | index($severity)) as $i
                            | $i != null and $i <= $threshold)))]
         | .[:10][]
         | "::error title=\(.vulnerability) in \(.component)::\(.severity)\(if .known_exploited then ", known exploited" else "" end): \(.url)"),
        (if $items | index("license") != null then
           [.evaluation.licenses.violations[]? | select(.verdict == "forbid")]
           | .[:10][]
           | "::error title=Forbidden license in \(.component)::\(.license // "unknown") (\(.licenses | join(", ")))"
         else empty end)
    ' "$response"
    fail "$error"
    ;;
  503) fail "${error:-the evaluation did not complete}" ;;
esac

echo "Uploaded to $project_url (HTTP $status${evaluation_status:+, evaluation $evaluation_status})"
