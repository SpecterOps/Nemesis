#/bin/bash

if [ -z "$1" ]
then
    echo "Runs bash or other commands in a pod. Usage: ./interact.sh <pod_name> [commands]"
    echo "    interact.sh pgadmin"
    echo "    interact.sh pgadmin -c pgadmin -- /bin/sh"
else
    POD_NAME=$(kubectl get pod -A | grep -v Terminating | grep $1 | awk '{print $2}')

    # check for more than two arguments
    if [ $# -gt 2 ]
    then
        kubectl exec --stdin --tty $POD_NAME ${@:1}
    else
        kubectl exec --stdin --tty $POD_NAME -- /bin/bash
    fi
fi