# For Nemesis-related docker components (i.e. it won't do this for any non-Nemesis stuff):)
# - Stops/removes the containers
# - Deletes/prunes the images
# - Deletes networks, and volumes
# - Cleans the builder cache

docker ps -a --filter "name=nemesis-*" --format '{{.Names}}' | xargs -r docker rm -v -f
docker images ghcr.io/specterops/nemesis/* --format '{{.Repository}}' 2>&1 | grep -Ev "base" | xargs -r docker rmi -f
docker images 'nemesis-*' --format '{{.Repository}}' 2>&1 | grep -Ev "base" | xargs -r docker rmi -f
docker network ls --filter "name=nemesis*" --format '{{.Name}}' | grep -Ev "base" | xargs -r docker network rm
docker volume ls --filter "name=nemesis*" --format '{{.Name}}' | grep -v "base" | xargs -r docker volume rm
docker builder prune -af
docker image prune -f
