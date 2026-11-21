#!/usr/bin/env bash
# Tests for tools/lib/env_secrets.sh. Run: ./tools/tests/test_env_secrets.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/env_secrets.sh
source "${SCRIPT_DIR}/../lib/env_secrets.sh"

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
value() { env_file_value "$TMP/.env" "$1"; }
is_random() { [[ "$1" =~ ^[0-9a-f]{48}$ ]]; }
contains() { [[ "$1" == *"$2"* ]]; }
not_contains() { [[ "$1" != *"$2"* ]]; }
is_random_salt() { [[ "$1" =~ ^sk-[0-9a-f]{48}$ ]]; }
line_count() { grep -cE "^$1=" "$TMP/.env"; }

# --- ensure_random_env_secret ---

printf 'OTHER=1\n' > "$TMP/.env"
ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123 > /dev/null
check "missing line: appends a random value" is_random "$(value LITELLM_ADMIN_PASSWORD)"
check "missing line: other lines kept" [ "$(value OTHER)" = "1" ]

printf 'LITELLM_ADMIN_PASSWORD=""\n' > "$TMP/.env"
ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123 > /dev/null
check "empty value: replaced with a random value" is_random "$(value LITELLM_ADMIN_PASSWORD)"
check "empty value: rewritten in place, not duplicated" [ "$(line_count LITELLM_ADMIN_PASSWORD)" = "1" ]

printf 'A=1\nLITELLM_ADMIN_PASSWORD=admin123\nB=2\n' > "$TMP/.env"
out="$(ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123)"
check "public default: replaced with a random value" is_random "$(value LITELLM_ADMIN_PASSWORD)"
check "public default: message says replaced" contains "$out" "Replaced the default"
check "public default: surrounding lines kept" [ "$(value A)$(value B)" = "12" ]
check "value is never printed" not_contains "$out" "$(value LITELLM_ADMIN_PASSWORD)"

printf "LITELLM_ADMIN_PASSWORD='admin123'\n" > "$TMP/.env"
ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123 > /dev/null
check "single-quoted default: replaced" is_random "$(value LITELLM_ADMIN_PASSWORD)"

printf 'LITELLM_ADMIN_PASSWORD="my-own-secret"\n' > "$TMP/.env"
out="$(ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123)"
check "custom value: kept" [ "$(value LITELLM_ADMIN_PASSWORD)" = "my-own-secret" ]
check "custom value: nothing printed" [ -z "$out" ]

printf 'HASURA_ADMIN_SECRET=pass456\nLITELLM_ADMIN_PASSWORD=keep\n' > "$TMP/.env"
ensure_random_env_secret "$TMP/.env" HASURA_ADMIN_SECRET pass456 > /dev/null
check "only the named variable changes" [ "$(value LITELLM_ADMIN_PASSWORD)" = "keep" ]
check "hasura default replaced" is_random "$(value HASURA_ADMIN_SECRET)"

chmod 600 "$TMP/.env"
printf 'X=admin123\n' > "$TMP/.env"
ensure_random_env_secret "$TMP/.env" X admin123 > /dev/null
check "file permissions preserved" [ "$(stat -c %a "$TMP/.env")" = "600" ]

rm -f "$TMP/.env"
check "missing env file: no-op success" ensure_random_env_secret "$TMP/.env" X admin123
check "missing env file: not created" [ ! -e "$TMP/.env" ]

# --- ensure_litellm_salt_key ---

printf 'OTHER=1\n' > "$TMP/.env"
ensure_litellm_salt_key "$TMP/.env" false > /dev/null
check "fresh install: random sk- salt" is_random_salt "$(value LITELLM_SALT_KEY)"

printf 'OTHER=1\n' > "$TMP/.env"
ensure_litellm_salt_key "$TMP/.env" true > /dev/null
check "existing data, default password: keeps the old salt" [ "$(value LITELLM_SALT_KEY)" = "sk-admin123" ]

printf 'LITELLM_ADMIN_PASSWORD="custom"\n' > "$TMP/.env"
ensure_litellm_salt_key "$TMP/.env" true > /dev/null
check "existing data, custom password: keeps the old salt" [ "$(value LITELLM_SALT_KEY)" = "sk-custom" ]

printf 'LITELLM_SALT_KEY="sk-mine"\n' > "$TMP/.env"
ensure_litellm_salt_key "$TMP/.env" false > /dev/null
check "explicit salt: kept" [ "$(value LITELLM_SALT_KEY)" = "sk-mine" ]

# The salt must be settled before the password rotates, as nemesis-ctl.sh does.
printf 'LITELLM_ADMIN_PASSWORD=admin123\n' > "$TMP/.env"
ensure_litellm_salt_key "$TMP/.env" true > /dev/null
ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123 > /dev/null
check "upgrade: salt keeps old value while password rotates" \
  [ "$(value LITELLM_SALT_KEY)" = "sk-admin123" ]
check "upgrade: password rotated" is_random "$(value LITELLM_ADMIN_PASSWORD)"

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES test(s) failed"
  exit 1
fi
echo "All tests passed"
