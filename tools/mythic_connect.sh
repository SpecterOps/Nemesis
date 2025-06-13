#!/bin/bash

# Wrapper script to connect to Mythic using Docker

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
CLI_OPTIONS=""
CONFIG_FILE_FOUND=false

for arg in "$@"; do
    # Check if argument is a file
    if [[ -f "$arg" ]]; then
        if [ "$CONFIG_FILE_FOUND" = true ]; then
            echo "Error: Only one configuration file is allowed"
            exit 1
        fi
        # It's a file - mount it to /config/ directory with original filename
        ABS_PATH=$(realpath "$arg")
        FILENAME=$(basename "$ABS_PATH")
        DOCKER_ARGS="$DOCKER_ARGS -v $ABS_PATH:/config/$FILENAME"
        CLI_OPTIONS="$CLI_OPTIONS -c /config/$FILENAME"
        CONFIG_FILE_FOUND=true
    elif [[ -d "$arg" ]]; then
        echo "Error: Directories are not supported. Please specify a configuration file."
        exit 1
    else
        # It's a CLI option (not a file or directory)
        CLI_OPTIONS="$CLI_OPTIONS $arg"
    fi
done

# Run the Docker command
docker compose run --rm $DOCKER_ARGS cli connect-mythic $CLI_OPTIONS