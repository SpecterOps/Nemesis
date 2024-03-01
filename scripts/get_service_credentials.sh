#/bin/bash

export BASIC_AUTH_USER=$(kubectl get secret operation-creds -o jsonpath="{.data.basic-auth-user}" | base64 -d)
export BASIC_AUTH_PASSWORD=$(kubectl get secret operation-creds -o jsonpath="{.data.basic-auth-password}" | base64 -d)
echo -e "\nBasic Auth:\n\t$BASIC_AUTH_USER:$BASIC_AUTH_PASSWORD"

export ES_USER=$(kubectl get secret elasticsearch-users -o jsonpath="{.data.username}" | base64 -d)
export ES_PASSWORD=$(kubectl get secret elasticsearch-users -o jsonpath="{.data.password}" | base64 -d)
echo -e "\nElastic/Kibana:\n\t$ES_USER:$ES_PASSWORD"

export ES_USER=$(kubectl get secret minio-creds -o jsonpath="{.data.root-user}" | base64 -d)
export ES_PASSWORD=$(kubectl get secret minio-creds -o jsonpath="{.data.root-password}" | base64 -d)
echo -e "\nMinio:\n\t$ES_USER:$ES_PASSWORD"

export ES_USER=$(kubectl get secret rabbitmq-creds -o jsonpath="{.data.rabbitmq-admin-user}" | base64 -d)
export ES_PASSWORD=$(kubectl get secret rabbitmq-creds -o jsonpath="{.data.rabbitmq-admin-password}" | base64 -d)
echo -e "\nRabbitMQ:\n\t$ES_USER:$ES_PASSWORD"

export AWS_ACCESS_KEY=$(kubectl get secret aws-creds -o jsonpath="{.data.aws_access_key_id}" | base64 -d)
export AWS_SECRET_KEY=$(kubectl get secret aws-creds -o jsonpath="{.data.aws_secret_key}" | base64 -d)
if [ $AWS_ACCESS_KEY != "not-applicable" ]; then
    echo -n "AWS_ACCESS_KEY:$AWS_ACCESS_KEY\nAWS_SECRET_KEY: $AWS_SECRET_KEY"
fi

echo ""