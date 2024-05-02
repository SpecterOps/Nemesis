#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
pushd "$SCRIPT_DIR/../" > /dev/null


DOCKER_IMAGES=$(cat dockerfiles/* | grep -o 'FROM .* ' | grep -Ev 'base|dependencies|debcommon|build|cobaltstrike|model_download|yara-rules' | sed -r 's/FROM (.*) as/\1/i' | sort -ui)
DEPLOYMENT_IMAGES=$(skaffold render | grep 'image: ' | sed -r 's/.*image: (.*)/\1/' | sort -u | grep -vE ':[a-z0-9]{64}$')

# combine and unique the two lists
IMAGES_TO_PULL=$(echo -e "${DOCKER_IMAGES}\n${DEPLOYMENT_IMAGES}" | sort -ui)

# If minikube is installed, use it's docker daemon
if command -v minikube &> /dev/null; then
    DOCKER_ENV=$(minikube docker-env)

    # check error
    if [ $? -ne 0 ]; then
        echo "Error: minikube not running?"
        exit 1
    fi

    eval $DOCKER_ENV
fi


echo "Pulling the following images"
echo "  From Dockerfiles           : ${DOCKER_IMAGES}"
echo "  From Deployment manifests  : ${DEPLOYMENT_IMAGES}"

# Pull each image
for image in $IMAGES_TO_PULL; do
    docker pull "${image}"
done

popd > /dev/null

