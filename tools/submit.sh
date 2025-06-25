#!/bin/bash

# Wrapper script to submit a job to the Nemesis CLI using Docker
# Added into the tools/ dir for convenience (near project root)

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COMPOSE_DIR="$( dirname "$SCRIPT_DIR" )"

cd "${COMPOSE_DIR}"

# Check if compose.cli.yaml exists
if [ ! -f compose.cli.yaml ]; then
    echo "Error: compose.cli.yaml not found in ${COMPOSE_DIR}"
    exit 1
fi

# Parse arguments to handle volume mounting and CLI options
DOCKER_ARGS=""
SUBMIT_ARGS=""
CLI_OPTIONS=""

for arg in "$@"; do
    # Check if argument is a file or directory path
    if [[ -f "$arg" ]]; then
        # It's a file
        ABS_PATH=$(realpath "$arg")
        DOCKER_ARGS="$DOCKER_ARGS -v $ABS_PATH:/data/$(basename "$ABS_PATH")"
        SUBMIT_ARGS="$SUBMIT_ARGS /data/$(basename "$ABS_PATH")"
    elif [[ -d "$arg" ]]; then
        # It's a directory
        ABS_PATH=$(realpath "$arg")
        DOCKER_ARGS="$DOCKER_ARGS -v $ABS_PATH:/data/$(basename "$ABS_PATH")"
        SUBMIT_ARGS="$SUBMIT_ARGS /data/$(basename "$ABS_PATH")"
    else
        # It's a CLI option (not a file or directory)
        CLI_OPTIONS="$CLI_OPTIONS $arg"
    fi
done

# Run the Docker command
docker compose -f compose.cli.yaml run --rm $DOCKER_ARGS cli submit $SUBMIT_ARGS $CLI_OPTIONS | sed '/^\[+\] Building/d'
