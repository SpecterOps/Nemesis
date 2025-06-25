#!/bin/bash

# Helper script to manage development and production Docker Compose services.

# Exit on any error, and on unset variables.
set -euo pipefail

# --- Functions ---
usage() {
  cat << EOF
Helper script to manage development and production services.

Usage: $0 {dev|prod} [options]

Options:
  --build         Build images before starting (includes base images for prod).
  --monitoring    Enable the monitoring profile (Grafana, Prometheus).
  --jupyter       Enable the Jupyter profile.

Examples:
  # Start production services from pre-built images
  $0 prod

  # Build and start production services with monitoring
  $0 prod --build --monitoring

  # Start development services with monitoring and jupyter
  $0 dev --monitoring --jupyter
EOF
  exit 1
}

# --- Configuration ---
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Assuming this script lives in a subdirectory like 'scripts/'
COMPOSE_DIR="$( dirname "$SCRIPT_DIR" )"

# --- Argument Parsing ---
if [[ $# -eq 0 || ( "$1" != "dev" && "$1" != "prod" ) ]]; then
  echo "Error: First argument must be 'dev' or 'prod'." >&2
  echo "" >&2
  usage
fi

ENVIRONMENT=$1
shift

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

# --- Main Logic ---
cd "${COMPOSE_DIR}"

# --- Pre-flight Checks ---
if [ ! -f ".env" ]; then
  echo "Error: Configuration file '.env' not found in ${COMPOSE_DIR}" >&2
  echo "Please create one by copying the example file:" >&2
  echo "" >&2
  echo "  cp env.example .env" >&2
  echo "" >&2
  echo "Then, review and customize the variables within it before running this script again." >&2
  exit 1
fi

# Array to hold the docker compose command and its arguments
declare -a DOCKER_CMD=("docker" "compose")
# Array to hold a command prefix, e.g., for setting environment variables.
declare -a CMD_PREFIX=()

# --- Build Command based on Flags ---

# 1. Handle Profiles and associated Environment Variables
if [ "$MONITORING" = "true" ]; then
  # Use the `env` utility to set the variable for the child process.
  CMD_PREFIX=( "env" "NEMESIS_MONITORING=enabled" )
  DOCKER_CMD+=("--profile" "monitoring")
fi

if [ "$JUPYTER" = "true" ]; then
  DOCKER_CMD+=("--profile" "jupyter")
fi

# 2. Handle Environment-specific files and build steps
if [ "$ENVIRONMENT" = "prod" ]; then
  echo "--- Preparing Production Environment ---"
  DOCKER_CMD+=("-f" "compose.yaml")

  if [ "$BUILD" = "true" ]; then
    echo "Build flag detected. Building images..."
    # Step 1: Build base images first, as per documentation
    echo "Building base images..."
    docker compose -f compose.base.yaml build

    # Add the production build file and --build flag
    DOCKER_CMD+=("-f" "compose.prod.build.yaml")
    DOCKER_CMD+=("up" "--build" "-d")
  else
    echo "Starting pre-built images..."
    DOCKER_CMD+=("up" "-d")
  fi

elif [ "$ENVIRONMENT" = "dev" ]; then
  echo "--- Preparing Development Environment ---"

  # CORRECTED: Dev environment also depends on base images, so build them first.
  echo "Ensuring base images are built..."
  docker compose -f compose.base.yaml build

  # For dev, Docker Compose automatically uses `compose.yaml` and `compose.override.yaml`.
  if [ "$BUILD" = "true" ]; then
    echo "Build flag detected. Building and starting dev-specific services..."
    DOCKER_CMD+=("up" "--build" "-d")
  else
    echo "Starting services (building dev-specific images if necessary)..."
    DOCKER_CMD+=("up" "-d")
  fi
fi

# --- Execute Command ---
echo
echo "Running command:"
(
  set -x
  if [ ${#CMD_PREFIX[@]} -eq 0 ]; then
    "${DOCKER_CMD[@]}"
  else
    "${CMD_PREFIX[@]}" "${DOCKER_CMD[@]}"
  fi
)

echo
echo '[+] start.sh script completed.'