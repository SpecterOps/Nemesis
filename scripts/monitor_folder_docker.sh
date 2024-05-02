#!/bin/bash

# Pulls down the specterops/nemesis-submit image that has the necessary Poetry/reqs
#   installed for ./script/submit_to_nemesis.sh, which functions as the entry point

if ! test -f submit_to_nemesis.yaml; then
    # first download the submit config if it doesn't exist
    wget https://raw.githubusercontent.com/SpecterOps/Nemesis/e8a75a5adac1ca93d3ddc5f144306071c302064c/cmd/enrichment/enrichment/cli/submit_to_nemesis/submit_to_nemesis.yaml
    sed -i 's|http://127.0.0.1:8080/api/|https://host.docker.internal:8080/api/|g' submit_to_nemesis.yaml
fi

echo -e "\nEdit './submit_to_nemesis.yaml' to reflect your Nemesis instance and then restart this script!"
echo -e "\nFiles copied into $PWD/submit/ will be submitted to Nemesis.\n"

docker run -it -v "$PWD/submit_to_nemesis.yaml":/config.yaml -v "$PWD/submit/":/submit/ --add-host=host.docker.internal:host-gateway -t specterops/nemesis-submit
