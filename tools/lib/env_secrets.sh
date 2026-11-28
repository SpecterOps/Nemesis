#!/bin/bash
# Helpers for generating deployment secrets in .env. Sourced by tools/nemesis-ctl.sh.
# Values are never printed; only the affected line of the env file is touched.

# Print the (unquoted) value of NAME from ENV_FILE, or nothing when unset.
# Follows the docker compose .env rules for comments: in an unquoted value, " #" (whitespace then #)
# starts an inline comment, while a "#" with no whitespace before it is part of the value; a quoted
# value keeps every "#" inside the quotes, and a comment may follow the closing quote.
env_file_value() {
  local env_file=$1 name=$2 raw value
  # (|| true: no matching line is fine under set -euo pipefail)
  raw="$({ grep -E "^[[:space:]]*${name}=" "$env_file" || true; } | tail -n 1 | cut -d= -f2-)"
  # Strip leading/trailing whitespace
  value="${raw#"${raw%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  if [[ "$value" =~ ^\"([^\"]*)\"[[:space:]]*(#.*)?$ ]] || [[ "$value" =~ ^\'([^\']*)\'[[:space:]]*(#.*)?$ ]]; then
    value="${BASH_REMATCH[1]}"
  elif [[ "$value" =~ ^\"(.*)\"$ ]] || [[ "$value" =~ ^\'(.*)\'$ ]]; then
    # Quotes inside a quoted value: keep everything between the outer quotes
    value="${BASH_REMATCH[1]}"
  elif [[ "$raw" =~ ^[[:space:]]+# ]]; then
    # NAME= # comment -> empty
    value=""
  else
    # Unquoted: drop an inline " # comment" and the whitespace before it
    value="${value%%[[:space:]]#*}"
    value="${value%"${value##*[![:space:]]}"}"
  fi
  printf '%s\n' "$value"
}

# Restrict ENV_FILE (which holds every deployment secret) to its owner. A failure (e.g. a file owned by
# another user) is reported but not fatal.
restrict_env_file_permissions() {
  local env_file=$1
  if ! chmod 600 "$env_file" 2> /dev/null; then
    echo "Warning: could not restrict permissions on ${env_file}; run: chmod 600 ${env_file}" >&2
  fi
  return 0
}

# Warn (without changing anything) when ENV_FILE is readable or writable by group/others. Files this
# script writes to are restricted automatically; an untouched .env is left to the operator, since some
# deployments share it deliberately.
warn_if_env_file_shared() {
  local env_file=$1 mode
  [ -f "$env_file" ] || return 0
  mode="$(stat -c %a "$env_file" 2> /dev/null || stat -f %Lp "$env_file" 2> /dev/null)" || return 0
  [[ "$mode" =~ ^[0-7]+$ ]] || return 0
  if (((8#$mode & 8#077) != 0)); then
    echo "Warning: ${env_file} (mode ${mode}) is accessible to other users and holds secrets; consider: chmod 600 ${env_file}" >&2
  fi
  return 0
}

# Set NAME="VALUE" in ENV_FILE, rewriting an existing line or appending a new one, then restrict the
# file to mode 0600.
set_env_file_value() {
  local env_file=$1 name=$2 value=$3 tmp
  if grep -qE "^[[:space:]]*${name}=" "$env_file"; then
    # The temporary copy holds every secret: mktemp creates it with mode 0600, next to the env file.
    tmp="$(umask 077 && mktemp "${env_file}.XXXXXX")" || return 1
    # Rewrite in place (cat > keeps the file's owner)
    if awk -v n="$name" -v v="$value" '$0 ~ "^[[:space:]]*" n "=" { print n "=\"" v "\""; next } { print }' \
      "$env_file" > "$tmp" && cat "$tmp" > "$env_file"; then
      rm -f "$tmp"
    else
      rm -f "$tmp"
      return 1
    fi
  else
    printf '\n%s="%s"\n' "$name" "$value" >> "$env_file"
  fi
  restrict_env_file_permissions "$env_file"
}

random_secret() {
  openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# Generate a random NAME in ENV_FILE only when it has no value there (or in the environment). A value the
# operator set is always used as-is; if it is one of the public DEFAULTS, print a warning and keep it.
# Usage: ensure_random_env_secret ENV_FILE NAME [DEFAULT...]
ensure_random_env_secret() {
  local env_file=$1 name=$2 current new default
  shift 2
  [ -f "$env_file" ] || return 0
  # docker compose prefers a value exported in the shell over .env
  current="${!name:-}"
  [ -n "$current" ] || current="$(env_file_value "$env_file" "$name")"
  if [ -n "$current" ]; then
    for default in "$@"; do
      if [ "$current" = "$default" ]; then
        echo "Warning: ${name} is set to the public default value; change it to a random value." >&2
      fi
    done
    return 0
  fi
  new="$(random_secret)"
  if [ -z "$new" ]; then
    echo "Error: could not generate a random ${name}; set one in .env" >&2
    return 1
  fi
  set_env_file_value "$env_file" "$name" "$new"
  echo "Generated a random ${name} in .env."
}

# LiteLLM encrypts provider credentials stored in its database with LITELLM_SALT_KEY, which used to
# equal the master key (by default the public "sk-admin123"). Changing it would make those credentials unreadable, so an
# existing deployment (EXISTING_DATA=true) keeps the old salt; a fresh one gets a random salt.
# Usage: ensure_litellm_salt_key ENV_FILE EXISTING_DATA
ensure_litellm_salt_key() {
  local env_file=$1 existing_data=$2 new old_password
  [ -f "$env_file" ] || return 0
  [ -n "${LITELLM_SALT_KEY:-}" ] && return 0
  [ -n "$(env_file_value "$env_file" LITELLM_SALT_KEY)" ] && return 0
  if [ "$existing_data" = "true" ]; then
    # The salt used to be "sk-${LITELLM_ADMIN_PASSWORD:-admin123}"
    old_password="${LITELLM_ADMIN_PASSWORD:-}"
    [ -n "$old_password" ] || old_password="$(env_file_value "$env_file" LITELLM_ADMIN_PASSWORD)"
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

# Percent-encode a value for the user or password part of a URL (bytes, so UTF-8 works too).
url_encode() {
  local LC_ALL=C value=$1 out="" char hex i
  for ((i = 0; i < ${#value}; i++)); do
    char="${value:i:1}"
    case "$char" in
      [A-Za-z0-9._~-]) out+="$char" ;;
      *)
        printf -v hex '%%%02X' "'$char"
        out+="$hex"
        ;;
    esac
  done
  printf '%s' "$out"
}

# compose.yaml builds connection URLs (postgresql://user:pass@host, amqp://...) from
# ${NAME_URLENC:-${NAME}}. Export NAME_URLENC for each credential so passwords with @ : / # % or
# spaces work (issue #81); a plain `docker compose` without them still works for URL-safe values.
# Values are never printed. A "$" is refused: compose expands it inside .env values, so the
# encoded copy would no longer match what compose passes to Postgres/RabbitMQ.
# Usage: export_url_encoded_credentials ENV_FILE NAME...
export_url_encoded_credentials() {
  local env_file=$1 name value bad=()
  shift
  for name in "$@"; do
    value="${!name:-}"
    [ -n "$value" ] || value="$(env_file_value "$env_file" "$name")"
    [ -n "$value" ] || continue
    if [[ "$value" == *'$'* ]]; then
      bad+=("$name")
      continue
    fi
    export "${name}_URLENC=$(url_encode "$value")"
  done
  if [ ${#bad[@]} -gt 0 ]; then
    echo "Error: ${bad[*]} contain(s) '\$', which docker compose expands inside .env values. Use a value without '\$'." >&2
    return 1
  fi
}

# For `stop`/`clean`: docker compose interpolates the whole file even for `down`, and refuses to run when a
# required (${NAME:?}) value is missing. Export a throwaway value for each NAME that has no value in the
# environment or ENV_FILE, so a deployment that never started (or has no .env) can still be torn down.
# Nothing is written to ENV_FILE and nothing is generated there.
# Usage: export_placeholders_for_compose_down ENV_FILE NAME...
# Export NEMESIS_LOGIN_HTPASSWD, the Nemesis login for Traefik's basic auth: "<user>:<apr1 hash>" from
# NEMESIS_USER (default n) and NEMESIS_PASSWORD (shell environment first, then ENV_FILE).
# apr1 rather than bcrypt: Traefik checks the hash on every request, and bcrypt costs ~50 ms of CPU each.
# The salt derives from the password, so the value is the same at every start and Traefik isn't recreated.
export_nemesis_login() {
  local env_file=$1 user password salt hash
  user="${NEMESIS_USER:-}"
  [ -n "$user" ] || user="$(env_file_value "$env_file" NEMESIS_USER)"
  user="${user:-n}"
  password="${NEMESIS_PASSWORD:-}"
  [ -n "$password" ] || password="$(env_file_value "$env_file" NEMESIS_PASSWORD)"
  if [ -z "$password" ]; then
    echo "Error: NEMESIS_PASSWORD is not set; set it in .env" >&2
    return 1
  fi
  if [[ "$user" == *:* ]]; then
    echo "Error: NEMESIS_USER can't contain ':'" >&2
    return 1
  fi
  salt="$(printf 'nemesis-login:%s' "$password" | openssl dgst -sha256 -r | cut -c1-8)"
  hash="$(printf '%s\n' "$password" | openssl passwd -apr1 -salt "$salt" -stdin)"
  if [ -z "$salt" ] || [[ "$hash" != '$apr1$'* ]]; then
    echo "Error: could not hash NEMESIS_PASSWORD (is openssl installed?)" >&2
    return 1
  fi
  export "NEMESIS_LOGIN_HTPASSWD=${user}:${hash}"
}

export_placeholders_for_compose_down() {
  local env_file=$1 name value
  shift
  for name in "$@"; do
    [ -n "${!name:-}" ] && continue
    value=""
    [ -f "$env_file" ] && value="$(env_file_value "$env_file" "$name")"
    [ -n "$value" ] && continue
    export "${name}=unused-by-compose-down"
  done
}
