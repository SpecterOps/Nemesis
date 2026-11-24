#!/bin/bash

# Wrapper script to monitor a folder using the Nemesis CLI with Docker
# Added into the tools/ dir for convenience (near project root)
#
# A CA file for Nemesis's certificate, given with --ca-file or NEMESIS_CA_FILE, is mounted read-only
# at /certs/nemesis-ca.pem in the container.


NEMESIS_CLI_IMAGE="${NEMESIS_CLI_IMAGE:-ghcr.io/specterops/nemesis/cli:latest}"
NEMESIS_NETWORK="${NEMESIS_NETWORK:-host}"
CONTAINER_CA_FILE=/certs/nemesis-ca.pem

# Parse arguments to handle volume mounting and CLI options
DOCKER_VOLUMES=()
ENV_ARGS=(-e NEMESIS_IGNORE_CERT_ERRORS)
MONITOR_PATH=""
CLI_OPTIONS=()
FOUND_DIRECTORY=false
CA_FILE="${NEMESIS_CA_FILE:-}"

args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
    arg="${args[$i]}"
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
    elif [[ "$arg" == "--ca-file" ]]; then
        i=$((i + 1))
        CA_FILE="${args[$i]:-}"
        if [[ -z "$CA_FILE" ]]; then
            echo "Error: --ca-file requires a file path"
            exit 1
        fi
    elif [[ "$arg" == --ca-file=* ]]; then
        CA_FILE="${arg#--ca-file=}"
    # Check if argument is a directory path
    elif [[ -d "$arg" ]]; then
        # It's a directory - this is what we'll monitor
        if [ "$FOUND_DIRECTORY" = true ]; then
            echo "Error: monitor command only accepts one directory path"
            exit 1
        fi
        ABS_PATH=$(realpath "$arg")
        DOCKER_VOLUMES+=(-v "$ABS_PATH:/data/$(basename "$ABS_PATH")")
        MONITOR_PATH="/data/$(basename "$ABS_PATH")"
        FOUND_DIRECTORY=true
    elif [[ -f "$arg" ]]; then
        # It's a file - not allowed for monitor command
        echo "Error: monitor command only accepts directories, not files: $arg"
        exit 1
    else
        # It's a CLI option
        CLI_OPTIONS+=("$arg")
    fi
    i=$((i + 1))
done

# Check if a directory was provided
if [ "$FOUND_DIRECTORY" = false ]; then
    echo "Error: monitor command requires a directory path"
    echo "Usage: $0 /path/to/directory [options]"
    exit 1
fi

if [[ -n "$CA_FILE" ]]; then
    if [[ ! -f "$CA_FILE" ]]; then
        echo "Error: CA file not found: $CA_FILE"
        exit 1
    fi
    DOCKER_VOLUMES+=(-v "$(realpath "$CA_FILE"):$CONTAINER_CA_FILE:ro")
    ENV_ARGS+=(-e "NEMESIS_CA_FILE=$CONTAINER_CA_FILE")
fi

# Run the Docker command
docker run \
  --rm \
  -ti \
  --network "$NEMESIS_NETWORK" \
  "${ENV_ARGS[@]}" \
  "${DOCKER_VOLUMES[@]}" \
  "$NEMESIS_CLI_IMAGE" \
  monitor "$MONITOR_PATH" "${CLI_OPTIONS[@]}"
