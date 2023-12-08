#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
pushd "$SCRIPT_DIR/../" > /dev/null

kubectl delete deployment postgres
sleep 5
kubectl apply -f kubernetes/postgres/deployment-dev.yaml

popd > /dev/null
