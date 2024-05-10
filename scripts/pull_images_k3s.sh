#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
pushd "$SCRIPT_DIR/../" > /dev/null

if [ $# -gt 0 ]; then
    # Grab the images required for building Nemesis
    IMAGES=$(skaffold render -m nemesis -m enrichment --digest-source=tag | grep 'image:' | sed 's/^[ \t]*image: //' | sed 's/"//g' | grep -v '^nemesis-' | sort -u)
else
    # Grab the images from the helm chart - this will pull the images from our Docker image registry
    IMAGES=$(helm template helm/nemesis/ | grep 'image:' | sed 's/^[ \t]*image: //' | sed 's/"//g' | sort -u)
fi

# Pull each image
for image in $IMAGES; do
    only_slashes="${image//[^\/]}"
    slash_count="${#only_slashes}"

    if ((slash_count == 0)); then
        # Format: Just single a library image name provided (e.g. debian)
        domain="docker.io"
        image="library/${image}"
    elif ((slash_count == 1)); then
        # Format: REPO/NAME (e.g. specterops/nemesis)
        domain="docker.io"
        image="${image}"
    elif ((slash_count == 2)); then
        # Format: DOMAIN.LOCAL/REPO/NAME (e.g., docker.io/specterops/nemesis)
        domain=$(echo -n $image | awk -F[/] '{print $1}')
        image=$(echo -n $image | sed "s/^${domain}\///")
    else
        echo "ERROR: too many slashes!"
        exit
    fi

    # Check if we need to add the tag
    if [[ ! "$image" =~ : ]]; then
        image="${image}:latest"
    fi

    k3s ctr image pull "${domain}/${image}"
done

popd > /dev/null