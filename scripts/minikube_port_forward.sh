#/bin/bash

HTTPS_SERVICE=$(minikube service list -n ingress-nginx | grep "https/443" | awk '{print $6}' | sed -E "s_^https?://__")

if [ -z "$1" ]
then
    FORWARD_PORT=8080
else
    if ! [[ $1 =~ ^-?[0-9]+$ ]]; then
        echo "Error: port to foward to must be a number!"; exit
    fi
    FORWARD_PORT=$1
fi

echo "Forwarding $HTTPS_SERVICE to $FORWARD_PORT via SSH. Navigate to https://localhost:$FORWARD_PORT. Use 'Ctrl+C' to stop the forward."
ssh -N -o StrictHostKeychecking=no -L 0.0.0.0:$FORWARD_PORT:$HTTPS_SERVICE localhost
