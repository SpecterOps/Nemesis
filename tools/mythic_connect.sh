#!/bin/bash

# Wrapper script to connect to Mythic using Docker
#
# Connector state (the discovery cursor and which files were uploaded) is kept in the Docker volume
# $NEMESIS_CONNECTOR_STATE_VOLUME (default "nemesis-connector-state"), mounted at /state. The container is
# removed after each run, so the state path is pinned to that volume and overrides any db.path in the
# config file; otherwise every restart would upload every Mythic file again.

NEMESIS_CLI_IMAGE="${NEMESIS_CLI_IMAGE:-ghcr.io/specterops/nemesis/cli:latest}"
NEMESIS_NETWORK="${NEMESIS_NETWORK:-host}"
NEMESIS_CONNECTOR_STATE_VOLUME="${NEMESIS_CONNECTOR_STATE_VOLUME:-nemesis-connector-state}"

# Parse arguments to handle volume mounting and CLI options
DOCKER_VOLUMES=()
CLI_OPTIONS=()
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
        DOCKER_VOLUMES+=(-v "$ABS_PATH:/config/$FILENAME:ro")
        CLI_OPTIONS+=(-c "/config/$FILENAME")
        CONFIG_FILE_FOUND=true
    elif [[ -d "$arg" ]]; then
        echo "Error: Directories are not supported. Please specify a configuration file."
        exit 1
    else
        # It's a CLI option (not a file or directory)
        CLI_OPTIONS+=("$arg")
    fi
done

echo "Connector state is kept in the Docker volume '$NEMESIS_CONNECTOR_STATE_VOLUME' (/state in the container)" >&2

# Run the Docker command
docker run \
  --rm \
  -ti \
  --network "$NEMESIS_NETWORK" \
  -e NEMESIS_IGNORE_CERT_ERRORS \
  -e XDG_STATE_HOME=/state \
  -e MYTHIC_SYNC_DB__PATH=/state/nemesis/connectors \
  -v "$NEMESIS_CONNECTOR_STATE_VOLUME:/state" \
  "${DOCKER_VOLUMES[@]}" \
  "$NEMESIS_CLI_IMAGE" \
  connect-mythic "${CLI_OPTIONS[@]}"
