#!/bin/bash

# Stop all containers
docker stop $(docker ps -aq)

# Remove all containers
docker rm $(docker ps -aq)

# Remove all images
docker rmi $(docker images -q) -f

# Remove all volumes
docker volume rm $(docker volume ls -q)

# Remove all networks (except default ones)
docker network rm $(docker network ls -q -f type=custom)

# Clean up build cache (this was missing!)
docker builder prune -a -f
docker buildx prune -a -f

# Final cleanup of any dangling resources
docker system prune -a --volumes -f
