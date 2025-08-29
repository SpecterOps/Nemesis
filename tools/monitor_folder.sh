#!/bin/bash

# Wrapper script to monitor a folder using the Nemesis CLI with Docker
# Added into the tools/ dir for convenience (near project root)


NEMESIS_CLI_IMAGE="${NEMESIS_CLI_IMAGE:-ghcr.io/specterops/nemesis/cli:latest}"
NEMESIS_NETWORK="${NEMESIS_NETWORK:-host}"

# Parse arguments to handle volume mounting and CLI options
DOCKER_VOLUME=""
MONITOR_PATH=""
CLI_OPTIONS=""
FOUND_DIRECTORY=false

for arg in "$@"; do
    # Check for help flags first
    if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
        # Pass help flag to the underlying CLI tool
        docker run \
          --rm \
          -ti \
          --network "$NEMESIS_NETWORK" \
          "$NEMESIS_CLI_IMAGE" \
          monitor --help
        exit 0
    # Check if argument is a directory path
    elif [[ -d "$arg" ]]; then
        # It's a directory - this is what we'll monitor
        if [ "$FOUND_DIRECTORY" = true ]; then
            echo "Error: monitor command only accepts one directory path"
            exit 1
        fi
        ABS_PATH=$(realpath "$arg")
        DOCKER_VOLUME="$DOCKER_VOLUME -v $ABS_PATH:/data/$(basename "$ABS_PATH")"
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
docker run \
  --rm \
  -ti \
  --network "$NEMESIS_NETWORK" \
  $DOCKER_VOLUME \
  "$NEMESIS_CLI_IMAGE" \
  monitor $MONITOR_PATH $CLI_OPTIONS