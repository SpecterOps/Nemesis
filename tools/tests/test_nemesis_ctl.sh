#!/usr/bin/env bash
# Tests for the secrets handling in tools/nemesis-ctl.sh (issue #158). Docker is replaced by a stub that
# records its arguments, so nothing is started. Run: ./tools/tests/test_nemesis_ctl.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(dirname "$SCRIPT_DIR")"
# Values exported in the shell take precedence over .env; keep them out of these tests.
unset HASURA_ADMIN_SECRET LITELLM_ADMIN_PASSWORD LITELLM_SALT_KEY POSTGRES_USER POSTGRES_PASSWORD RABBITMQ_USER \
  RABBITMQ_PASSWORD POSTGRES_USER_URLENC POSTGRES_PASSWORD_URLENC RABBITMQ_USER_URLENC RABBITMQ_PASSWORD_URLENC

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
contains() { [[ "$1" == *"$2"* ]]; }

# A copy of the repo layout nemesis-ctl.sh needs: tools/{nemesis-ctl.sh,lib/env_secrets.sh}, the
# version generator (stubbed) and the frontend public dir.
REPO="$TMP/repo"
mkdir -p "$REPO/tools/lib" "$REPO/projects/frontend/public" "$TMP/bin"
cp "$TOOLS_DIR/nemesis-ctl.sh" "$REPO/tools/"
cp "$TOOLS_DIR/lib/env_secrets.sh" "$REPO/tools/lib/"
printf '#!/bin/sh\necho "{}" > "$1"\n' > "$REPO/tools/generate-version.sh"
chmod +x "$REPO/tools/generate-version.sh"

# docker stub: `docker volume inspect` reports whether $FAKE_VOLUME_EXISTS; every compose call records
# the secrets docker compose would see in its environment.
cat > "$TMP/bin/docker" << 'EOF'
#!/usr/bin/env bash
if [ "$1" = "volume" ]; then
  [ "${FAKE_VOLUME_EXISTS:-false}" = "true" ]
  exit
fi
{
  echo "ARGS=$*"
  for n in HASURA_ADMIN_SECRET LITELLM_SALT_KEY LITELLM_ADMIN_PASSWORD POSTGRES_PASSWORD_URLENC; do
    echo "$n=${!n-<unset>}"
  done
} >> "$DOCKER_LOG"
EOF
chmod +x "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH" DOCKER_LOG="$TMP/docker.log"

run_ctl() { # run_ctl ARGS... -> sets OUT and RC
  : > "$DOCKER_LOG"
  OUT="$("$REPO/tools/nemesis-ctl.sh" "$@" 2>&1)" && RC=0 || RC=$?
  LOG="$(< "$DOCKER_LOG")"
}
fingerprint() { sha256sum < "$REPO/.env"; stat -c %a "$REPO/.env"; }

BASE_ENV='POSTGRES_USER=nemesis
POSTGRES_PASSWORD="p@ss"
RABBITMQ_USER=nemesis
RABBITMQ_PASSWORD=rabbit
'

# --- stop/clean never generate or write secrets ---
for action in stop clean; do
  printf '%s' "$BASE_ENV" > "$REPO/.env"
  chmod 644 "$REPO/.env"
  before="$(fingerprint)"
  FAKE_VOLUME_EXISTS=true run_ctl "$action" prod
  check "$action: succeeds" [ "$RC" = 0 ]
  check "$action: .env content and mode unchanged" [ "$(fingerprint)" = "$before" ]
  check "$action: nothing reported as generated or kept" bash -c '[[ "$1" != *Generated* && "$1" != *Kept* ]]' _ "$OUT"
  check "$action: compose down sees a throwaway salt, not the legacy default" contains "$LOG" "LITELLM_SALT_KEY=unused-by-compose-down"
  check "$action: compose down sees throwaway required secrets" contains "$LOG" "HASURA_ADMIN_SECRET=unused-by-compose-down"
done
contains "$LOG" "ARGS=compose -f compose.yaml down --volumes" && rc=0 || rc=1
check "clean: runs compose down --volumes" [ "$rc" = 0 ]

printf '%sHASURA_ADMIN_SECRET="real-secret"\n' "$BASE_ENV" > "$REPO/.env"
run_ctl stop prod
check "stop: a secret already in .env is not replaced by a placeholder" contains "$LOG" "HASURA_ADMIN_SECRET=<unset>"

# A "$" in a password blocks start (compose would expand it) but not stop/clean (issue #158c)
printf 'POSTGRES_PASSWORD="ab$cd"\n' > "$REPO/.env"
for action in stop clean; do
  run_ctl "$action" dev
  check "$action: works with a '\$' in a password" [ "$RC" = 0 ]
done
check "stop/clean: no URL-encoded credentials needed" contains "$LOG" "POSTGRES_PASSWORD_URLENC=<unset>"

rm -f "$REPO/.env"
run_ctl stop prod
check "stop without .env: still runs compose down" [ "$RC" = 0 ]
check "stop without .env: .env not created" [ ! -e "$REPO/.env" ]

# --- start keeps generating secrets ---
printf '%s' "$BASE_ENV" > "$REPO/.env"
chmod 644 "$REPO/.env"
run_ctl start prod
check "start: succeeds" [ "$RC" = 0 ]
# shellcheck source=../lib/env_secrets.sh
source "$TOOLS_DIR/lib/env_secrets.sh"
check "start: generates HASURA_ADMIN_SECRET" [ -n "$(env_file_value "$REPO/.env" HASURA_ADMIN_SECRET)" ]
check "start: generates a random salt for a fresh deployment" \
  bash -c '[[ "$1" =~ ^sk-[0-9a-f]{48}$ ]]' _ "$(env_file_value "$REPO/.env" LITELLM_SALT_KEY)"
check "start: generates LITELLM_ADMIN_PASSWORD" [ -n "$(env_file_value "$REPO/.env" LITELLM_ADMIN_PASSWORD)" ]
check "start: .env restricted to 0600 after writing" [ "$(stat -c %a "$REPO/.env")" = "600" ]
check "start: exports URL-encoded credentials" contains "$LOG" "POSTGRES_PASSWORD_URLENC=p%40ss"
check "start: no placeholder values" bash -c '[[ "$1" != *unused-by-compose-down* ]]' _ "$LOG"

printf '%s' "$BASE_ENV" > "$REPO/.env"
FAKE_VOLUME_EXISTS=true run_ctl start prod
check "start with existing data: keeps the legacy salt" [ "$(env_file_value "$REPO/.env" LITELLM_SALT_KEY)" = "sk-admin123" ]

printf '%sHASURA_ADMIN_SECRET=a\nLITELLM_SALT_KEY=b\nLITELLM_ADMIN_PASSWORD=c\n' "$BASE_ENV" > "$REPO/.env"
chmod 640 "$REPO/.env"
run_ctl start prod
check "start, nothing to write: warns about a shared .env" contains "$OUT" "chmod 600"
check "start, nothing to write: mode left alone" [ "$(stat -c %a "$REPO/.env")" = "640" ]

printf 'POSTGRES_PASSWORD="ab$cd"\n' > "$REPO/.env"
run_ctl start prod
check "start: refuses a '\$' in a password" [ "$RC" = 1 ]
check "start: nothing run when refusing" [ -z "$LOG" ]

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES test(s) failed"
  exit 1
fi
echo "All tests passed"
