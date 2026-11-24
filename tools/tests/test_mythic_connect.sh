#!/usr/bin/env bash
# Tests for tools/mythic_connect.sh (issue #152). Docker is replaced by a stub that records its arguments, so
# nothing is run. Run: ./tools/tests/test_mythic_connect.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONNECT="$(dirname "$SCRIPT_DIR")/mythic_connect.sh"
unset NEMESIS_CONNECTOR_STATE_VOLUME NEMESIS_CA_FILE MYTHIC_CA_FILE

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
has_arg() { # has_arg VALUE: VALUE is one whole docker argument
  local a
  for a in "${ARGV[@]}"; do [[ "$a" == "$1" ]] && return 0; done
  return 1
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
cat > "$TMP/bin/docker" << 'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$DOCKER_ARGV"
EOF
chmod +x "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH" DOCKER_ARGV="$TMP/argv" NEMESIS_CLI_IMAGE="test/cli:1"
IMAGE="test/cli:1"

run_connect() { # run_connect ARGS... -> ARGV, OUT, RC
  rm -f "$DOCKER_ARGV"
  OUT="$(cd "$TMP" && "$CONNECT" "$@" 2>&1)" && RC=0 || RC=$?
  ARGV=()
  if [ -f "$DOCKER_ARGV" ]; then
    while IFS= read -r line; do ARGV+=("$line"); done < "$DOCKER_ARGV"
  fi
}

mkdir -p "$TMP/cfg dir"
echo "project: x" > "$TMP/cfg dir/settings_mythic.yaml"

# --- state persists in a named volume ---
run_connect "$TMP/cfg dir/settings_mythic.yaml" --debug
check "docker run invoked" [ "$RC" = 0 ]
check "state volume mounted at /state" has_pair -v "nemesis-connector-state:/state"
check "XDG_STATE_HOME points into the volume" has_pair -e "XDG_STATE_HOME=/state"
check "db.path pinned to the volume" has_pair -e "MYTHIC_SYNC_DB__PATH=/state/nemesis/connectors"
check "state location is announced" bash -c '[[ "$1" == *nemesis-connector-state* ]]' _ "$OUT"

# --- config file with a space in its path is mounted read-only as one argument ---
check "config mounted read-only" has_pair -v "$TMP/cfg dir/settings_mythic.yaml:/config/settings_mythic.yaml:ro"
check "CLI gets the config and options" \
  [ "$(after_image)" = "connect-mythic -c /config/settings_mythic.yaml --debug" ]

# --- the volume name can be overridden ---
NEMESIS_CONNECTOR_STATE_VOLUME=team-a-state run_connect "$TMP/cfg dir/settings_mythic.yaml"
check "custom state volume" has_pair -v "team-a-state:/state"

# --- no config: options only ---
run_connect --showconfig
check "no config: options passed through" [ "$(after_image)" = "connect-mythic --showconfig" ]
check "no config: state volume still mounted" has_pair -v "nemesis-connector-state:/state"

# --- errors ---
run_connect "$TMP/cfg dir/settings_mythic.yaml" "$TMP/cfg dir/settings_mythic.yaml"
check "two config files rejected" [ "$RC" = 1 ]
run_connect "$TMP/cfg dir"
check "directory rejected" [ "$RC" = 1 ]
run_connect --debug
check "NEMESIS_IGNORE_CERT_ERRORS forwarded by name" has_pair -e NEMESIS_IGNORE_CERT_ERRORS

# --- CA files ---
echo pem > "$TMP/nemesis ca.pem"
echo pem > "$TMP/mythic-ca.pem"
NEMESIS_CA_FILE="$TMP/nemesis ca.pem" MYTHIC_CA_FILE="$TMP/mythic-ca.pem" \
  run_connect "$TMP/cfg dir/settings_mythic.yaml"
check "Nemesis CA mounted read-only" has_pair -v "$TMP/nemesis ca.pem:/certs/nemesis-ca.pem:ro"
check "Nemesis CA overrides nemesis.ca_file" has_pair -e "MYTHIC_SYNC_NEMESIS__CA_FILE=/certs/nemesis-ca.pem"
check "Mythic CA mounted read-only" has_pair -v "$TMP/mythic-ca.pem:/certs/mythic-ca.pem:ro"
check "Mythic CA overrides networking.ca_file" has_pair -e "MYTHIC_SYNC_NETWORKING__CA_FILE=/certs/mythic-ca.pem"
check "CA files are not taken as the config" \
  [ "$(after_image)" = "connect-mythic -c /config/settings_mythic.yaml" ]
MYTHIC_CA_FILE="$TMP/missing.pem" run_connect "$TMP/cfg dir/settings_mythic.yaml"
check "missing CA file rejected" [ "$RC" = 1 ]
run_connect "$TMP/cfg dir/settings_mythic.yaml"
check "no CA files: no CA overrides" bash -c '! grep -q CA_FILE "$1"' _ "$DOCKER_ARGV"

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES test(s) failed"
  exit 1
fi
echo "All tests passed"
