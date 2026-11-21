#!/bin/bash
# Helpers for generating deployment secrets in .env. Sourced by tools/nemesis-ctl.sh.
# Values are never printed; only the affected line of the env file is touched.

# Print the (unquoted) value of NAME from ENV_FILE, or nothing when unset.
env_file_value() {
  local env_file=$1 name=$2
  # (|| true: no matching line is fine under set -euo pipefail)
  { grep -E "^[[:space:]]*${name}=" "$env_file" || true; } | tail -n 1 | cut -d= -f2- \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

# Set NAME="VALUE" in ENV_FILE, rewriting an existing line or appending a new one.
set_env_file_value() {
  local env_file=$1 name=$2 value=$3
  if grep -qE "^[[:space:]]*${name}=" "$env_file"; then
    # Rewrite in place (cat > keeps the file's owner and permissions)
    awk -v n="$name" -v v="$value" '$0 ~ "^[[:space:]]*" n "=" { print n "=\"" v "\""; next } { print }' \
      "$env_file" > "${env_file}.tmp" && cat "${env_file}.tmp" > "$env_file" && rm -f "${env_file}.tmp"
  else
    printf '\n%s="%s"\n' "$name" "$value" >> "$env_file"
  fi
}

random_secret() {
  openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# Generate a random NAME in ENV_FILE when it is unset/empty or equals one of the public DEFAULTS.
# Usage: ensure_random_env_secret ENV_FILE NAME [DEFAULT...]
ensure_random_env_secret() {
  local env_file=$1 name=$2 current new default
  shift 2
  [ -f "$env_file" ] || return 0
  current="$(env_file_value "$env_file" "$name")"
  if [ -n "$current" ]; then
    local is_default=false
    for default in "$@"; do
      [ "$current" = "$default" ] && is_default=true
    done
    [ "$is_default" = "true" ] || return 0
  fi
  new="$(random_secret)"
  if [ -z "$new" ]; then
    echo "Error: could not generate a random ${name}; set one in .env" >&2
    return 1
  fi
  set_env_file_value "$env_file" "$name" "$new"
  if [ -n "$current" ]; then
    echo "Replaced the default ${name} in .env with a random one."
  else
    echo "Generated a random ${name} in .env."
  fi
}

# LiteLLM encrypts provider credentials stored in its database with LITELLM_SALT_KEY, which used to
# equal the master key (by default the public "sk-admin123"). Changing it would make those credentials unreadable, so an
# existing deployment (EXISTING_DATA=true) keeps the old salt; a fresh one gets a random salt.
# Usage: ensure_litellm_salt_key ENV_FILE EXISTING_DATA
ensure_litellm_salt_key() {
  local env_file=$1 existing_data=$2 new old_password
  [ -f "$env_file" ] || return 0
  [ -n "$(env_file_value "$env_file" LITELLM_SALT_KEY)" ] && return 0
  if [ "$existing_data" = "true" ]; then
    # The salt used to be "sk-${LITELLM_ADMIN_PASSWORD:-admin123}"
    old_password="$(env_file_value "$env_file" LITELLM_ADMIN_PASSWORD)"
    set_env_file_value "$env_file" LITELLM_SALT_KEY "sk-${old_password:-admin123}"
    echo "Kept the previous LITELLM_SALT_KEY in .env so existing LiteLLM credentials stay readable."
    return 0
  fi
  new="$(random_secret)"
  if [ -z "$new" ]; then
    echo "Error: could not generate a random LITELLM_SALT_KEY; set one in .env" >&2
    return 1
  fi
  set_env_file_value "$env_file" LITELLM_SALT_KEY "sk-${new}"
  echo "Generated a random LITELLM_SALT_KEY in .env."
}
