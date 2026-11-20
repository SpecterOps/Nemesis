#!/bin/bash

# Helper script to manage development and production Docker Compose services.

# Exit on any error, and on unset variables.
set -euo pipefail

# --- Functions ---
usage() {
  cat << EOF
Helper script to manage development and production services.

Usage: $0 <action> <environment> [options]

Actions:
  start           Build (optional) and start services in the background.
  stop            Stop and remove services (containers and networks).
  clean           Stop and remove services AND delete associated data volumes.

Environments:
  dev             Development environment.
  prod            Production environment.

Options:
  --build         Build images before starting (not for 'stop' or 'clean' actions).
  --monitoring    Enable the monitoring profile (Grafana, Prometheus).
  --jupyter       Enable the Jupyter profile.
  --llm           Enable the LLM services profile.

Examples:
  # Start production services with monitoring
  $0 start prod --monitoring

  # Stop all production services that were started with the monitoring profile
  $0 stop prod --monitoring

  # Stop services and remove all associated data volumes for the dev environment
  $0 clean dev

  # Build and start all development services
  $0 start dev --build
EOF
  exit 1
}

# --- Configuration ---
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Assuming this script lives in a subdirectory like 'scripts/'
COMPOSE_DIR="$( dirname "$SCRIPT_DIR" )"

# --- Argument Parsing ---
if [[ $# -lt 2 ]]; then
  echo "Error: Missing required arguments." >&2
  echo "" >&2
  usage
fi

ACTION=$1
shift
ENVIRONMENT=$1
shift

# Validate action
if [[ "$ACTION" != "start" && "$ACTION" != "stop" && "$ACTION" != "clean" ]]; then
  echo "Error: Invalid action '$ACTION'. Must be 'start', 'stop', or 'clean'." >&2
  echo "" >&2
  usage
fi

# Validate environment
if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "prod" ]]; then
  echo "Error: Invalid environment '$ENVIRONMENT'. Must be 'dev' or 'prod'." >&2
  echo "" >&2
  usage
fi

BUILD=false
MONITORING=false
JUPYTER=false
LLM=false

# Parse optional flags
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --build) BUILD=true; shift ;;
    --monitoring) MONITORING=true; shift ;;
    --jupyter) JUPYTER=true; shift ;;
    --llm) LLM=true; shift ;;
    *) echo "Unknown option: $1" >&2; echo "" >&2; usage ;;
  esac
done

# Validate flag combinations
if ( [ "$ACTION" = "stop" ] || [ "$ACTION" = "clean" ] ) && [ "$BUILD" = "true" ]; then
  echo "Error: The --build flag cannot be used with the 'stop' or 'clean' actions." >&2
  exit 1
fi

# --- Main Logic ---
cd "${COMPOSE_DIR}"

# --- Pre-flight Checks (only for 'start' action) ---
if [ "$ACTION" = "start" ]; then
  if [ ! -f ".env" ]; then
    echo "Error: Configuration file '.env' not found in ${COMPOSE_DIR}" >&2
    echo "Please create one by copying the example file:" >&2
    echo "" >&2
    echo "  cp env.example .env" >&2
    echo "" >&2
    echo "Then, review and customize the variables within it before running this script again." >&2
    exit 1
  fi
fi

# --- Hasura admin secret: generate a random one when unset or still the old public default ---
# Only that line of .env is touched and the value is never printed.
ensure_hasura_admin_secret() {
  local env_file=".env" current new
  [ -f "$env_file" ] || return 0
  current="$(grep -E '^[[:space:]]*HASURA_ADMIN_SECRET=' "$env_file" | tail -n 1 | cut -d= -f2- \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")"
  if [ -n "$current" ] && [ "$current" != "pass456" ]; then
    return 0
  fi
  new="$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  if [ -z "$new" ]; then
    echo "Error: could not generate a random HASURA_ADMIN_SECRET; set one in .env" >&2
    exit 1
  fi
  if grep -qE '^[[:space:]]*HASURA_ADMIN_SECRET=' "$env_file"; then
    # Rewrite in place (cat > keeps the file's owner and permissions)
    awk -v v="$new" '/^[[:space:]]*HASURA_ADMIN_SECRET=/ { print "HASURA_ADMIN_SECRET=\"" v "\""; next } { print }' \
      "$env_file" > "${env_file}.tmp" && cat "${env_file}.tmp" > "$env_file" && rm -f "${env_file}.tmp"
  else
    printf '\nHASURA_ADMIN_SECRET="%s"\n' "$new" >> "$env_file"
  fi
  if [ -n "$current" ]; then
    echo "Replaced the default HASURA_ADMIN_SECRET in .env with a random one."
  else
    echo "Generated a random HASURA_ADMIN_SECRET in .env."
  fi
}
ensure_hasura_admin_secret

# --- Build Command ---
declare -a DOCKER_CMD=("docker" "compose")
declare -a ENV_VARS=()

# 1. Handle Profiles and associated Environment Variables
if [ "$MONITORING" = "true" ]; then
  ENV_VARS+=("NEMESIS_MONITORING=enabled")
  DOCKER_CMD+=("--profile" "monitoring")
fi

if [ "$JUPYTER" = "true" ]; then
  DOCKER_CMD+=("--profile" "jupyter")
fi

if [ "$LLM" = "true" ]; then
  DOCKER_CMD+=("--profile" "llm")
  if [ -n "${PHOENIX_ENABLED:-}" ] && [ "$PHOENIX_ENABLED" != "true" ] && [ "$PHOENIX_ENABLED" != "false" ]; then
    echo "Error: PHOENIX_ENABLED must be 'true' or 'false', got '$PHOENIX_ENABLED'." >&2
    exit 1
  fi
  ENV_VARS+=("PHOENIX_ENABLED=${PHOENIX_ENABLED:-true}")
fi

# 2. Handle Environment-specific files
if [ "$ENVIRONMENT" = "prod" ]; then
  DOCKER_CMD+=("-f" "compose.yaml")
  # Production build file is only needed for a build+start command
  if [ "$ACTION" = "start" ] && [ "$BUILD" = "true" ]; then
    DOCKER_CMD+=("-f" "compose.prod.build.yaml")
  fi
else
  # Always build in dev environment to catch local changes.
  # This only affects the `start` action, as validated earlier.
  BUILD=true
fi

# 3. Handle Action
if [ "$ACTION" = "start" ]; then
  echo "--- Preparing to Start Services for '$ENVIRONMENT' environment ---"

  # Generate version.json for local builds
  echo "Generating version information..."
  "${SCRIPT_DIR}/generate-version.sh" "${COMPOSE_DIR}/version.json" "local"
  # Prod images bake it in at build time (dev mounts the repo-root copy)
  cp "${COMPOSE_DIR}/version.json" "${COMPOSE_DIR}/projects/frontend/public/version.json"

  if [ "$BUILD" = "true" ]; then
    # Base images must be built for both dev and prod before starting
    echo "Ensuring base images are built..."
    docker compose -f compose.base.yaml build

    echo "Building and starting services..."
    DOCKER_CMD+=("up" "--build" "-d")
  else
    echo "Starting services..."
    DOCKER_CMD+=("up" "-d")
  fi

elif [ "$ACTION" = "stop" ]; then
  echo "--- Preparing to Stop Services for '$ENVIRONMENT' environment ---"
  DOCKER_CMD+=("down")

elif [ "$ACTION" = "clean" ]; then
  echo "--- Preparing to Clean Services and Volumes for '$ENVIRONMENT' environment ---"
  # The --volumes flag removes named volumes defined in the compose file.
  DOCKER_CMD+=("down" "--volumes")
fi

# --- Execute Command ---
echo
echo "Running command:"

# Build final command with environment variables if needed
if [ ${#ENV_VARS[@]} -gt 0 ]; then
  FINAL_CMD=("env" "${ENV_VARS[@]}" "${DOCKER_CMD[@]}")
else
  FINAL_CMD=("${DOCKER_CMD[@]}")
fi

(
  set -x # This makes the shell print the exact command before executing it.
  "${FINAL_CMD[@]}"
)

echo
if [ "$ACTION" = "start" ]; then
  echo "Services are up and running."
elif [ "$ACTION" = "clean" ]; then
  echo "Services, containers, and volumes have been stopped and removed."
else
  echo "Services and containers have been stopped and removed."
fi