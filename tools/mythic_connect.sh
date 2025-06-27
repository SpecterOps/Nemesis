#!/bin/bash

# Wrapper script to connect to Mythic using Docker


NEMESIS_CLI_IMAGE="${NEMESIS_CLI_IMAGE:-ghcr.io/specterops/nemesis/cli:latest}"
NEMESIS_NETWORK="${NEMESIS_NETWORK:-host}"

# Parse arguments to handle volume mounting and CLI options
DOCKER_VOLUME=""
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
        DOCKER_VOLUME="$DOCKER_VOLUME -v $ABS_PATH:/config/$FILENAME"
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
docker run \
  --rm \
  -ti \
  --network "$NEMESIS_NETWORK" \
  $DOCKER_VOLUME \
  "$NEMESIS_CLI_IMAGE" \
  connect-mythic $CLI_OPTIONS