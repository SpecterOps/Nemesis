#/bin/bash

export BASIC_AUTH_USER=$(kubectl get secret basic-auth -o jsonpath="{.data.username}" | base64 -d)
export BASIC_AUTH_PASSWORD=$(kubectl get secret basic-auth -o jsonpath="{.data.password}" | base64 -d)
echo -e "\nBasic Auth:\n\t$BASIC_AUTH_USER:$BASIC_AUTH_PASSWORD"

# export ES_USER=$(kubectl get secret elasticsearch-users -o jsonpath="{.data.username}" | base64 -d)
# export ES_PASSWORD=$(kubectl get secret elasticsearch-users -o jsonpath="{.data.password}" | base64 -d)
# echo -e "\nElastic/Kibana:\n\t$ES_USER:$ES_PASSWORD"

export JUPYTER_TOKEN=$(kubectl get secret jupyter-creds -o jsonpath="{.data.token}" | base64 -d)
echo -e "\nJupyter token:\n\t$JUPYTER_TOKEN"

export MINIO_USER=$(kubectl get secret minio-creds -o jsonpath="{.data.root-user}" | base64 -d)
export MINION_PASSWORD=$(kubectl get secret minio-creds -o jsonpath="{.data.root-password}" | base64 -d)
echo -e "\nMinio:\n\t$MINIO_USER:$MINION_PASSWORD"

export RABBITMQ_USER=$(kubectl get secret rabbitmq-creds -o jsonpath="{.data.rabbitmq-admin-user}" | base64 -d)
export RABBITMQ_PASSWORD=$(kubectl get secret rabbitmq-creds -o jsonpath="{.data.rabbitmq-admin-password}" | base64 -d)
echo -e "\nRabbitMQ:\n\t$RABBITMQ_USER:$RABBITMQ_PASSWORD"

export AWS_ACCESS_KEY=$(kubectl get secret aws-creds -o jsonpath="{.data.aws-access-key-id}" | base64 -d)
export AWS_SECRET_KEY=$(kubectl get secret aws-creds -o jsonpath="{.data.aws-secret-key}" | base64 -d)
if [ $AWS_ACCESS_KEY != "not-applicable" ]; then
    echo -n "AWS_ACCESS_KEY:$AWS_ACCESS_KEY\nAWS_SECRET_KEY: $AWS_SECRET_KEY"
fi

echo ""