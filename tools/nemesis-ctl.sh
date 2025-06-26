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

# Parse optional flags
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --build) BUILD=true; shift ;;
    --monitoring) MONITORING=true; shift ;;
    --jupyter) JUPYTER=true; shift ;;
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

# --- Build Command ---
declare -a DOCKER_CMD=("docker" "compose")
declare -a CMD_PREFIX=()

# 1. Handle Profiles and associated Environment Variables
if [ "$MONITORING" = "true" ]; then
  CMD_PREFIX=( "env" "NEMESIS_MONITORING=enabled" )
  DOCKER_CMD+=("--profile" "monitoring")
fi

if [ "$JUPYTER" = "true" ]; then
  DOCKER_CMD+=("--profile" "jupyter")
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
(
  set -x # This makes the shell print the exact command before executing it.
  "${CMD_PREFIX[@]}" "${DOCKER_CMD[@]}"
)

echo
if [ "$ACTION" = "start" ]; then
  echo "Services are up and running."
elif [ "$ACTION" = "clean" ]; then
  echo "Services, containers, and volumes have been stopped and removed."
else
  echo "Services and containers have been stopped and removed."
fi