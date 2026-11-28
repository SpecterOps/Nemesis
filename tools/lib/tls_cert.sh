#!/bin/bash
# TLS certificate for Traefik (infra/traefik/certs/server.crt + server.key). Sourced by tools/nemesis-ctl.sh after
# lib/env_secrets.sh; the CLI port is projects/cli/cli/ctl/tlscert.py and must behave the same.

# The self-signed certificate that used to ship in the repository: its private key is public, so never serve it
PUBLIC_REPO_CERT_SHA256="F6:15:1C:09:96:94:AB:01:3C:F5:BE:AD:5C:3D:13:22:5D:1E:7B:16:62:BE:4A:36:88:2A:32:CD:83:78:22:6C"
# Marks certificates this script made, so it renews only its own (a user's certificate only gets a warning)
SELF_SIGNED_ORG="Nemesis self-signed"
RENEW_WITHIN_SECONDS=$((30 * 24 * 3600))

# Hostname or IP from NEMESIS_URL (environment first, then ENV_FILE), or nothing
nemesis_url_host() {
  local env_file=$1 url
  url="${NEMESIS_URL:-}"
  [ -n "$url" ] || url="$(env_file_value "$env_file" NEMESIS_URL)"
  url="${url#*://}"
  url="${url%%/*}"
  url="${url##*@}"
  case "$url" in
    \[*) url="${url#[}"; url="${url%%]*}" ;; # [IPv6]:port
    *) url="${url%%:*}" ;;
  esac
  printf '%s' "$url"
}

# Export NEMESIS_TLS_CERT_SHA256, the certificate's fingerprint: Traefik reads the certificate only when it loads its
# configuration, so compose.yaml passes it this value to recreate Traefik whenever the certificate changes
export_tls_certificate_fingerprint() {
  local fingerprint
  fingerprint="$(openssl x509 -in "$1/server.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
  export "NEMESIS_TLS_CERT_SHA256=${fingerprint}"
}

# Make sure CERT_DIR holds a usable certificate: create a self-signed one when there is none, renew a self-signed
# one that expires within 30 days, and replace the certificate that used to ship in the repository. A certificate
# you supplied is never replaced, only warned about when it is about to expire.
ensure_tls_certificate() {
  local cert_dir=$1 env_file=$2 crt key fingerprint host san
  crt="$cert_dir/server.crt"
  key="$cert_dir/server.key"
  if [ -f "$crt" ] && [ -f "$key" ]; then
    fingerprint="$(openssl x509 -in "$crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
    if [ "$fingerprint" = "$PUBLIC_REPO_CERT_SHA256" ]; then
      echo "Replacing the TLS certificate that used to ship with Nemesis (its private key is public)."
    elif openssl x509 -in "$crt" -noout -checkend "$RENEW_WITHIN_SECONDS" > /dev/null 2>&1; then
      return 0
    elif openssl x509 -in "$crt" -noout -subject 2>/dev/null | grep -q "$SELF_SIGNED_ORG"; then
      echo "Renewing the self-signed TLS certificate (it expires within 30 days)."
    else
      echo "Warning: the TLS certificate $crt expires within 30 days (or has expired); replace it." >&2
      return 0
    fi
  fi

  host="$(nemesis_url_host "$env_file")"
  san="DNS:localhost,IP:127.0.0.1"
  if [ -n "$host" ] && [ "$host" != localhost ] && [ "$host" != 127.0.0.1 ]; then
    if [[ "$host" =~ ^[0-9.]+$ || "$host" == *:* ]]; then
      san="$san,IP:$host"
    else
      san="$san,DNS:$host"
    fi
  fi
  mkdir -p "$cert_dir"
  if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 365 \
    -subj "/O=${SELF_SIGNED_ORG}/CN=${host:-localhost}" -addext "subjectAltName=${san}" \
    -keyout "$key.new" -out "$crt.new" > /dev/null 2>&1; then
    rm -f "$key.new" "$crt.new"
    echo "Error: could not create a TLS certificate in $cert_dir (is openssl installed?)" >&2
    return 1
  fi
  chmod 600 "$key.new"
  mv -f "$key.new" "$key"
  mv -f "$crt.new" "$crt"
  echo "Created a self-signed TLS certificate for ${host:-localhost} in ${cert_dir}" \
    "(put your own server.crt/server.key there to use a different one)."
}
