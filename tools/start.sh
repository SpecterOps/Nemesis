#!/bin/bash

# Helper script to startup all services
# - Note: not suitable for use in dev mode yet

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COMPOSE_DIR="$( dirname "$SCRIPT_DIR" )"

cd "${COMPOSE_DIR}"

build_base_images() {
  # Build base image first
  docker compose -f docker-compose.base.yml build
}

# Build and run based on environment
if [ "$1" = "prod" ]; then
  shift
  build_base_images
  ENVIRONMENT=prod docker compose -f "$COMPOSE_DIR/docker-compose.yml" -f "$COMPOSE_DIR/docker-compose.prod.yml" pull
  ENVIRONMENT=prod docker compose -f "$COMPOSE_DIR/docker-compose.yml" -f "$COMPOSE_DIR/docker-compose.prod.yml" build
  ENVIRONMENT=prod docker compose -f "$COMPOSE_DIR/docker-compose.yml" -f "$COMPOSE_DIR/docker-compose.prod.yml" "$@" up
elif [ "$1" = "dev" ]; then
  shift
  build_base_images
  ENVIRONMENT=dev docker compose -f "$COMPOSE_DIR/docker-compose.yml" pull
  ENVIRONMENT=dev docker compose -f "$COMPOSE_DIR/docker-compose.yml" build
  ENVIRONMENT=dev docker compose -f "$COMPOSE_DIR/docker-compose.yml" "$@" up
else
  echo "Usage: $0 {dev|prod} [additional 'docker compose up' arguments]"
  exit 1
fi