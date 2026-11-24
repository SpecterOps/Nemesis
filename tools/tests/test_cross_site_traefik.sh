#!/usr/bin/env bash
# Runs infra/traefik/config/cross-site.yml and auth.yml in a throwaway Traefik (same image as compose.yaml) in front of
# a stub backend, and checks which browser-shaped requests it refuses. Requires docker, curl and openssl.
# Run: ./tools/tests/test_cross_site_traefik.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="$(grep -oE 'image: traefik:v[0-9.]+' "$ROOT/compose.yaml" | head -1 | cut -d' ' -f2)"
NAME="nemesis-cross-site-test-$$"
TMP="$(mktemp -d)"
cleanup() {
  docker rm -f "$NAME" "$NAME-backend" > /dev/null 2>&1 || true
  docker network rm "$NAME" > /dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/config"
cp "$ROOT/infra/traefik/config/cross-site.yml" "$ROOT/infra/traefik/config/auth.yml" "$TMP/config/"
# Stand-in for the docker-label routers: everything else goes to the backend, at a normal priority
cat > "$TMP/config/backend.yml" << EOF
http:
  routers:
    backend:
      entryPoints: [websecure]
      tls: {}
      rule: PathPrefix(\`/\`)
      priority: 100
      service: backend
    login:
      entryPoints: [websecure]
      tls: {}
      rule: PathPrefix(\`/login-test\`)
      priority: 200
      middlewares: [auth]
      service: backend
  services:
    backend:
      loadBalancer:
        servers: [{url: "http://$NAME-backend:80"}]
EOF

docker network create "$NAME" > /dev/null
docker run -d --name "$NAME-backend" --network "$NAME" traefik/whoami:v1.10.3 > /dev/null
# Two users and a trailing comma, as BASIC_AUTH_USERS may be written in .env
USERS="alice:$(openssl passwd -apr1 alicepw),bob:$(openssl passwd -apr1 bobpw),"
docker run -d --name "$NAME" --network "$NAME" -p 127.0.0.1::443 -e "BASIC_AUTH_USERS=$USERS" -v "$TMP/config:/config:ro" "$IMAGE" \
  --providers.file.directory=/config --entrypoints.websecure.address=:443 --log.level=ERROR > /dev/null
PORT="$(docker port "$NAME" 443/tcp | head -1 | cut -d: -f2)"
URL="https://127.0.0.1:$PORT"

for _ in $(seq 50); do
  [ "$(curl -sk -o /dev/null -w '%{http_code}' "$URL/")" = "200" ] && break
  sleep 0.2
done

FAILURES=0
expect() { # expect STATUS DESCRIPTION CURL_ARGS...
  local want=$1 desc=$2
  shift 2
  local got
  got="$(curl -sk -o /dev/null -w '%{http_code}' "$@")"
  if [ "$got" = "$want" ]; then
    echo "ok   - $desc ($got)"
  else
    echo "FAIL - $desc: expected $want, got $got"
    FAILURES=$((FAILURES + 1))
  fi
}
XS=(-H 'Sec-Fetch-Site: cross-site')
NAV=(-H 'Sec-Fetch-Mode: navigate')

# --- refused: another site made the browser send it ---
expect 403 "cross-site form POST to Hasura" -X POST "${XS[@]}" "${NAV[@]}" -H 'Content-Type: text/plain' --data x "$URL/hasura/v1/graphql"
expect 403 "cross-site form POST to RabbitMQ" -X POST "${XS[@]}" "${NAV[@]}" --data x "$URL/rabbitmq/api/definitions"
expect 403 "cross-site form POST to web-api" -X POST "${XS[@]}" "${NAV[@]}" --data x "$URL/api/files"
expect 403 "cross-site fetch POST" -X POST "${XS[@]}" -H 'Sec-Fetch-Mode: cors' --data x "$URL/hasura/v1/graphql"
expect 403 "same-site (sibling subdomain) POST" -X POST -H 'Sec-Fetch-Site: same-site' --data x "$URL/hasura/v1/graphql"
expect 403 "header value in another case" -X POST -H 'Sec-Fetch-Site: Cross-Site' --data x "$URL/hasura/v1/graphql"
expect 403 "Origin null (sandboxed frame), no Sec-Fetch-Site" -X POST -H 'Origin: null' --data x "$URL/api/files"
expect 403 "cross-site PUT" -X PUT "${XS[@]}" --data x "$URL/rabbitmq/api/users/x"
expect 403 "cross-site WebSocket" "${XS[@]}" -H 'Sec-Fetch-Mode: websocket' "$URL/hasura/v1/graphql"
expect 403 "cross-site script/img load" "${XS[@]}" -H 'Sec-Fetch-Mode: no-cors' "$URL/env.js"
expect 403 "cross-site link into /api (e.g. a report download)" "${XS[@]}" "${NAV[@]}" "$URL/api/reports/system/pdf"
expect 403 "cross-site POST navigation outside /api" -X POST "${XS[@]}" "${NAV[@]}" --data x "$URL/jupyter/api/contents"

# --- allowed ---
expect 200 "API client with no browser headers (CLI, connectors)" -X POST --data x "$URL/api/files"
expect 200 "the Nemesis UI itself (same-origin)" -X POST -H 'Sec-Fetch-Site: same-origin' --data x "$URL/hasura/v1/graphql"
expect 200 "typed URL or bookmark" -H 'Sec-Fetch-Site: none' "${NAV[@]}" "$URL/files"
expect 200 "link from another site into the UI" "${XS[@]}" "${NAV[@]}" "$URL/files/123"
expect 200 "HEAD link check from another site" -I "${XS[@]}" "${NAV[@]}" "$URL/"
expect 200 "same-origin Origin header" -X POST -H "Origin: $URL" --data x "$URL/hasura/v1/graphql"

# --- the Nemesis login (auth.yml) ---
expect 401 "login required" "$URL/login-test"
expect 200 "first BASIC_AUTH_USERS entry logs in" -u alice:alicepw "$URL/login-test"
expect 200 "second BASIC_AUTH_USERS entry logs in" -u bob:bobpw "$URL/login-test"
expect 401 "wrong password" -u alice:bobpw "$URL/login-test"
expect 401 "user from the empty trailing entry" -u ":" "$URL/login-test"

# --- plain HTTP is never routed ---
expect 404 "plain HTTP to the HTTPS port reaches no backend" "http://127.0.0.1:$PORT/"
expect 404 "plain HTTP with a login reaches no backend" -u alice:alicepw "http://127.0.0.1:$PORT/login-test"

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES check(s) failed"
  exit 1
fi
echo "All checks passed"
