#!/usr/bin/env bash
# Tests for tools/monitor_folder.sh. Docker is replaced by a stub that records its arguments, so nothing is
# run. Run: ./tools/tests/test_monitor_folder.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITOR="$(dirname "$SCRIPT_DIR")/monitor_folder.sh"
unset NEMESIS_CA_FILE

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0

check() { # check DESCRIPTION CONDITION...
  local desc=$1
  shift
  if "$@"; then
    echo "ok   - $desc"
  else
    echo "FAIL - $desc"
    FAILURES=$((FAILURES + 1))
  fi
}
has_pair() { # has_pair FLAG VALUE: FLAG immediately followed by VALUE
  local i
  for ((i = 0; i + 1 < ${#ARGV[@]}; i++)); do
    [[ "${ARGV[$i]}" == "$1" && "${ARGV[$((i + 1))]}" == "$2" ]] && return 0
  done
  return 1
}
after_image() { # the arguments passed to the CLI, space-joined
  local a seen=false out=()
  for a in "${ARGV[@]}"; do
    if $seen; then out+=("$a"); fi
    [[ "$a" == "$IMAGE" ]] && seen=true
  done
  echo "${out[*]}"
}

mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" << 'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$DOCKER_ARGV"
STUB
chmod +x "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH" DOCKER_ARGV="$TMP/argv" NEMESIS_CLI_IMAGE="test/cli:1"
IMAGE="test/cli:1"

run_monitor() { # run_monitor ARGS... -> ARGV, OUT, RC
  rm -f "$DOCKER_ARGV"
  OUT="$(cd "$TMP" && "$MONITOR" "$@" 2>&1)" && RC=0 || RC=$?
  ARGV=()
  if [ -f "$DOCKER_ARGV" ]; then
    while IFS= read -r line; do ARGV+=("$line"); done < "$DOCKER_ARGV"
  fi
}

mkdir -p "$TMP/loot dir"
echo pem > "$TMP/ca.pem"

# --- basic ---
run_monitor "$TMP/loot dir" --project p1
check "docker run invoked" [ "$RC" = 0 ]
check "directory with a space mounted as one argument" has_pair -v "$TMP/loot dir:/data/loot dir"
check "CLI gets the mounted directory and options" [ "$(after_image)" = "monitor /data/loot dir --project p1" ]
check "NEMESIS_IGNORE_CERT_ERRORS forwarded" has_pair -e NEMESIS_IGNORE_CERT_ERRORS
check "no CA file: none passed" bash -c '! grep -q CA_FILE "$1"' _ "$DOCKER_ARGV"

# --- CA file from the option ---
run_monitor "$TMP/loot dir" --ca-file "$TMP/ca.pem"
check "--ca-file: accepted (not rejected as a file argument)" [ "$RC" = 0 ]
check "--ca-file: mounted read-only" has_pair -v "$TMP/ca.pem:/certs/nemesis-ca.pem:ro"
check "--ca-file: container path passed via NEMESIS_CA_FILE" has_pair -e "NEMESIS_CA_FILE=/certs/nemesis-ca.pem"
check "--ca-file: not passed as a CLI option" [ "$(after_image)" = "monitor /data/loot dir" ]
run_monitor "$TMP/loot dir" "--ca-file=$TMP/ca.pem"
check "--ca-file=PATH form" has_pair -v "$TMP/ca.pem:/certs/nemesis-ca.pem:ro"

# --- CA file from the environment ---
NEMESIS_CA_FILE="$TMP/ca.pem" run_monitor "$TMP/loot dir"
check "NEMESIS_CA_FILE: mounted read-only" has_pair -v "$TMP/ca.pem:/certs/nemesis-ca.pem:ro"
check "NEMESIS_CA_FILE: rewritten to the container path" has_pair -e "NEMESIS_CA_FILE=/certs/nemesis-ca.pem"

# --- errors ---
run_monitor "$TMP/loot dir" --ca-file "$TMP/missing.pem"
check "missing CA file rejected" [ "$RC" = 1 ]
run_monitor "$TMP/loot dir" --ca-file
check "--ca-file without a value rejected" [ "$RC" = 1 ]
run_monitor "$TMP/ca.pem"
check "plain file argument still rejected" [ "$RC" = 1 ]
run_monitor --project p1
check "no directory rejected" [ "$RC" = 1 ]

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES test(s) failed"
  exit 1
fi
echo "All tests passed"
