#!/usr/bin/env bash
# Tests for tools/lib/env_secrets.sh. Run: ./tools/tests/test_env_secrets.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/env_secrets.sh
source "${SCRIPT_DIR}/../lib/env_secrets.sh"
# Values exported in the shell take precedence over .env; keep them out of these tests.
unset HASURA_ADMIN_SECRET LITELLM_ADMIN_PASSWORD LITELLM_SALT_KEY X POSTGRES_USER POSTGRES_PASSWORD RABBITMQ_USER RABBITMQ_PASSWORD \
  POSTGRES_USER_URLENC POSTGRES_PASSWORD_URLENC RABBITMQ_USER_URLENC RABBITMQ_PASSWORD_URLENC

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
out="$(ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123 2>&1)"
check "public default: kept, never replaced" [ "$(value LITELLM_ADMIN_PASSWORD)" = "admin123" ]
check "public default: warns" contains "$out" "public default"
check "public default: surrounding lines kept" [ "$(value A)$(value B)" = "12" ]

printf "LITELLM_ADMIN_PASSWORD='admin123'\n" > "$TMP/.env"
out="$(ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123 2>&1)"
check "single-quoted default: kept" [ "$(value LITELLM_ADMIN_PASSWORD)" = "admin123" ]
check "single-quoted default: warns" contains "$out" "public default"

printf 'LITELLM_ADMIN_PASSWORD=""\n' > "$TMP/.env"
out="$(ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123)"
check "generated value is never printed" not_contains "$out" "$(value LITELLM_ADMIN_PASSWORD)"

printf 'OTHER=1\n' > "$TMP/.env"
LITELLM_ADMIN_PASSWORD=from-shell ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123 > /dev/null
check "value exported in the shell: .env left alone" [ -z "$(value LITELLM_ADMIN_PASSWORD)" ]

printf 'LITELLM_ADMIN_PASSWORD="my-own-secret"\n' > "$TMP/.env"
out="$(ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123)"
check "custom value: kept" [ "$(value LITELLM_ADMIN_PASSWORD)" = "my-own-secret" ]
check "custom value: nothing printed" [ -z "$out" ]

printf 'HASURA_ADMIN_SECRET=\nLITELLM_ADMIN_PASSWORD=keep\n' > "$TMP/.env"
ensure_random_env_secret "$TMP/.env" HASURA_ADMIN_SECRET pass456 > /dev/null
check "only the named variable changes" [ "$(value LITELLM_ADMIN_PASSWORD)" = "keep" ]
check "empty hasura secret generated" is_random "$(value HASURA_ADMIN_SECRET)"

printf 'HASURA_ADMIN_SECRET=pass456\n' > "$TMP/.env"
ensure_random_env_secret "$TMP/.env" HASURA_ADMIN_SECRET pass456 > /dev/null 2>&1
check "hasura public default kept" [ "$(value HASURA_ADMIN_SECRET)" = "pass456" ]

chmod 600 "$TMP/.env"
printf 'X=\n' > "$TMP/.env"
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

printf 'OTHER=1\n' > "$TMP/.env"
LITELLM_ADMIN_PASSWORD=shellpw ensure_litellm_salt_key "$TMP/.env" true > /dev/null
check "existing data, password exported in the shell: keeps that old salt" [ "$(value LITELLM_SALT_KEY)" = "sk-shellpw" ]

printf 'OTHER=1\n' > "$TMP/.env"
LITELLM_SALT_KEY=sk-shell ensure_litellm_salt_key "$TMP/.env" false > /dev/null
check "salt exported in the shell: .env left alone" [ -z "$(value LITELLM_SALT_KEY)" ]

# The salt must be settled before a missing password is generated, as nemesis-ctl.sh does.
printf 'OTHER=1\n' > "$TMP/.env"
ensure_litellm_salt_key "$TMP/.env" true > /dev/null
ensure_random_env_secret "$TMP/.env" LITELLM_ADMIN_PASSWORD admin123 > /dev/null
check "upgrade: salt keeps the old default while the missing password is generated" \
  [ "$(value LITELLM_SALT_KEY)" = "sk-admin123" ]
check "upgrade: password generated" is_random "$(value LITELLM_ADMIN_PASSWORD)"

# --- url_encode / export_url_encoded_credentials (issue #81) ---
check "url_encode keeps unreserved characters" [ "$(url_encode 'Az09-_.~')" = "Az09-_.~" ]
check "url_encode escapes URL delimiters" [ "$(url_encode 'p@ss:w/rd?#%[]')" = "p%40ss%3Aw%2Frd%3F%23%25%5B%5D" ]
check "url_encode escapes spaces, plus and quotes" [ "$(url_encode "a b+\"'\\")" = "a%20b%2B%22%27%5C" ]
check "url_encode encodes UTF-8 bytes" [ "$(url_encode 'é')" = "%C3%A9" ]
check "url_encode of empty is empty" [ -z "$(url_encode '')" ]
# Round trip through Python's decoder, as libpq/amqp clients decode
pw='p@ss w:rd/#?%&=+"\'"'"'é!*'
check "url_encode round-trips" [ "$(python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$(url_encode "$pw")")" = "$pw" ]

printf 'POSTGRES_USER="nemesis"\nPOSTGRES_PASSWORD="p@ss:w/rd#1"\nRABBITMQ_USER=nemesis\nRABBITMQ_PASSWORD="r@bbit %%"\n' > "$TMP/.env"
out="$(export_url_encoded_credentials "$TMP/.env" POSTGRES_USER POSTGRES_PASSWORD RABBITMQ_USER RABBITMQ_PASSWORD 2>&1; \
  printf '%s|%s|%s|%s' "$POSTGRES_USER_URLENC" "$POSTGRES_PASSWORD_URLENC" "$RABBITMQ_USER_URLENC" "$RABBITMQ_PASSWORD_URLENC")"
check "exports encoded credentials from .env" [ "$out" = "nemesis|p%40ss%3Aw%2Frd%231|nemesis|r%40bbit%20%25" ]

out="$(POSTGRES_PASSWORD='sh@ll' export_url_encoded_credentials "$TMP/.env" POSTGRES_PASSWORD; printf '%s' "$POSTGRES_PASSWORD_URLENC")"
check "a value exported in the shell wins over .env" [ "$out" = "sh%40ll" ]

out="$(export_url_encoded_credentials "$TMP/.env" POSTGRES_PASSWORD 2>&1)"
check "prints nothing" [ -z "$out" ]

printf 'POSTGRES_PASSWORD="ab$cd"\n' > "$TMP/.env"
out="$(export_url_encoded_credentials "$TMP/.env" POSTGRES_PASSWORD 2>&1)" && rc=0 || rc=$?
check "refuses a \$ (compose expands it in .env)" [ "$rc" = 1 ]
check "names the variable, not the value" bash -c '[[ "$1" == *POSTGRES_PASSWORD* && "$1" != *abcd* && "$1" != *'"'"'ab$cd'"'"'* ]]' _ "$out"

printf 'OTHER=1\n' > "$TMP/.env"
out="$(export_url_encoded_credentials "$TMP/.env" POSTGRES_PASSWORD; printf '%s' "${POSTGRES_PASSWORD_URLENC-unset}")"
check "unset credential: nothing exported (compose reports it)" [ "$out" = "unset" ]

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES test(s) failed"
  exit 1
fi
echo "All tests passed"
