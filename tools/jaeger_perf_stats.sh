#!/usr/bin/env bash
set -euo pipefail

########################################
# Config
########################################
JAEGER_URL="https://localhost:7443/jaeger/api/traces"
AUTH_USER="n"
AUTH_PASS="n"
LIMIT=20000

# --- Set A: service=file-enrichment, activity||... + orchestration||... ops
SERVICE_A="file-enrichment"
ops_a=(
  "orchestration||enrichment_pipeline_workflow"
  "activity||get_basic_analysis"
  "activity||run_enrichment_modules"
  "activity||check_file_linkings"
  "activity||handle_file_if_plaintext"
  "activity||publish_enriched_file"
  "activity||publish_findings_alerts"
)

# --- Set B: service=file_enrichment, spans inside run_enrichment_modules
SERVICE_B="file_enrichment"
PARENT_OPERATION_B="run_enrichment_modules"
ops_b=(
  "run_enrichment_modules"
  "download_file"
  "determine_modules_to_process"
  "enrichment.yara"
  "enrichment.filename"
)

########################################
# Shared jq stats program
########################################
jq_stats_prog='
  [
    .data[]
    .spans[]
    | select(.operationName == $opname)
    | .duration
  ] as $durs
  |
  if ($durs | length) == 0 then
    {
      operation: $opname,
      count: 0,
      min_ms: null,
      max_ms: null,
      avg_ms: null
    }
  else
    {
      operation: $opname,
      count: ($durs | length),
      min_ms: ($durs | min / 1000),
      max_ms: ($durs | max / 1000),
      avg_ms: (($durs | add / ($durs | length)) / 1000)
    }
  end
'

########################################
# Helper: print header for a table
########################################
print_header() {
  printf "%-45s %10s %12s %12s %12s\n" "Operation" "Count" "Min (ms)" "Max (ms)" "Avg (ms)"
  printf "%s\n" "------------------------------------------------------------------------------------------------------------------------"
}

########################################
# TABLE 1: service=file-enrichment
########################################
echo ""
echo "TABLE 1: service=${SERVICE_A}"
print_header

for op in "${ops_a[@]}"; do
  op_encoded=$(printf '%s' "$op" | jq -sRr @uri)

  resp=$(
    curl -sk --user "${AUTH_USER}:${AUTH_PASS}" \
      "${JAEGER_URL}?service=${SERVICE_A}&operation=${op_encoded}&limit=${LIMIT}"
  )

  result=$(echo "$resp" | jq -r --arg opname "$op" \
    "$jq_stats_prog | [.operation, .count, .min_ms, .max_ms, .avg_ms] | @tsv")

  op_name=$(echo "$result" | cut -f1)
  count=$(echo "$result" | cut -f2)
  min_ms=$(echo "$result" | cut -f3)
  max_ms=$(echo "$result" | cut -f4)
  avg_ms=$(echo "$result" | cut -f5)

  printf "%-45s %10s %12s %12s %12s\n" \
    "$op_name" "$count" "${min_ms:-null}" "${max_ms:-null}" "${avg_ms:-null}"
done

########################################
# TABLE 2: service=file_enrichment (inner spans)
########################################
echo ""
echo "TABLE 2: service=${SERVICE_B}, parent operation=${PARENT_OPERATION_B}"
print_header

resp_b=$(
  curl -sk --user "${AUTH_USER}:${AUTH_PASS}" \
    "${JAEGER_URL}?service=${SERVICE_B}&operation=${PARENT_OPERATION_B}&limit=${LIMIT}"
)

for op in "${ops_b[@]}"; do
  result=$(echo "$resp_b" | jq -r --arg opname "$op" \
    "$jq_stats_prog | [.operation, .count, .min_ms, .max_ms, .avg_ms] | @tsv")

  op_name=$(echo "$result" | cut -f1)
  count=$(echo "$result" | cut -f2)
  min_ms=$(echo "$result" | cut -f3)
  max_ms=$(echo "$result" | cut -f4)
  avg_ms=$(echo "$result" | cut -f5)

  printf "%-45s %10s %12s %12s %12s\n" \
    "$op_name" "$count" "${min_ms:-null}" "${max_ms:-null}" "${avg_ms:-null}"
done

