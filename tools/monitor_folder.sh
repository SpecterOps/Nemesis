#!/bin/bash

# Wrapper script to monitor a folder using the Nemesis CLI with Docker
# Added into the tools/ dir for convenience (near project root)

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COMPOSE_DIR="$( dirname "$SCRIPT_DIR" )"

cd "${COMPOSE_DIR}"

# Check if docker-compose.yml exists
if [ ! -f docker-compose.yml ]; then
    echo "Error: docker-compose.yml not found in ${COMPOSE_DIR}"
    exit 1
fi

# Set dummy values for required variables if they're not already set
# This allows the CLI to run without requiring all the main stack variables
export GRAFANA_ADMIN_USER="${GRAFANA_ADMIN_USER:-dummy}"
export GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-dummy}"
export MINIO_ROOT_USER="${MINIO_ROOT_USER:-dummy}"
export MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-dummy}"
export RABBITMQ_USER="${RABBITMQ_USER:-dummy}"
export RABBITMQ_PASSWORD="${RABBITMQ_PASSWORD:-dummy}"
export POSTGRES_USER="${POSTGRES_USER:-dummy}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-dummy}"
export JUPYTER_PASSWORD="${JUPYTER_PASSWORD:-dummy}"
export NEMESIS_URL="${NEMESIS_URL:-https://localhost:7443}"

# Parse arguments to handle volume mounting and CLI options
DOCKER_ARGS=""
MONITOR_PATH=""
CLI_OPTIONS=""
FOUND_DIRECTORY=false

for arg in "$@"; do
    # Check if argument is a directory path
    if [[ -d "$arg" ]]; then
        # It's a directory - this is what we'll monitor
        if [ "$FOUND_DIRECTORY" = true ]; then
            echo "Error: monitor command only accepts one directory path"
            exit 1
        fi
        ABS_PATH=$(realpath "$arg")
        DOCKER_ARGS="$DOCKER_ARGS -v $ABS_PATH:/data/$(basename "$ABS_PATH")"
        MONITOR_PATH="/data/$(basename "$ABS_PATH")"
        FOUND_DIRECTORY=true
    elif [[ -f "$arg" ]]; then
        # It's a file - not allowed for monitor command
        echo "Error: monitor command only accepts directories, not files: $arg"
        exit 1
    else
        # It's a CLI option
        CLI_OPTIONS="$CLI_OPTIONS $arg"
    fi
done

# Check if a directory was provided
if [ "$FOUND_DIRECTORY" = false ]; then
    echo "Error: monitor command requires a directory path"
    echo "Usage: $0 /path/to/directory [options]"
    exit 1
fi

# Run the Docker command
docker compose run --rm $DOCKER_ARGS cli monitor $MONITOR_PATH $CLI_OPTIONS