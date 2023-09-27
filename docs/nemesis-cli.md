# Nemesis CLI
`nemesis-cli.py` is responsible for configuring Nemesis's Kubernete's environment. It does things such as installing the [Nginx](https://kubernetes.github.io/ingress-nginx/) [ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/#what-is-ingress), the [Elastic Cloud on Kubernetes(ECK)](https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-overview.html) [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/), [Minio](https://min.io/) (if configured), the [Kubernetes Metrics Server](https://github.com/kubernetes-sigs/metrics-server), and  Nemesis's configuration objects ([ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/) and [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)).

The `nemesis-cli.py` script can accept configuration options through (in descending order of precendence):
- Environment variables
- A YAML config file. By default, it will attempt to load `nemesis.config`, but an alternative may be specified with `nemesis-cli.py -c /path/to/nemesis.config`. See [nemesis.config.example](../nemesis.config.example) for a simple example.
- Command line arguments

If a required configuration value is not supplied, nemesis-cli will check if it is already set in the Kubernetes environment. If not, a prompt will ask the user to input a value for the setting.

# Configuration Options
| Environment Variable      | `nemesis.config` entry  | cli argument              | Description                                                                                                                                                                              |
|---------------------------|-------------------------|---------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AWS_REGION                | aws_region              | --aws_region              | The region for the AWS S3 bucket/KMS key                                                                                                                                                 |
| AWS_BUCKET                | aws_bucket              | --aws_bucket              | The AWS S3 bucket name                                                                                                                                                                   |
| AWS_KMS_AWS_KMS_KEY_ALIAS | aws_kms_key_alias       | --aws_kms_key_alias       | The alias of the AWS KMS key                                                                                                                                                             |
| AWS_ACCESS_KEY_ID         | aws_access_key_id       | --aws_access_key_id       | The AWS access key ID                                                                                                                                                                    |
| AWS_SECRET_KEY            | aws_secret_key          | --aws_secret_key          | The AWS secret key                                                                                                                                                                       |
| MINIO_ROOT_USER           | minio_root_user         | --minio_root_user         | The username for Minio (it not using AWS)                                                                                                                                                |
| MINIO_ROOT_PASSWORD       | minio_root_password     | --minio_root_password     | The password for Minio (it not using AWS)                                                                                                                                                |
| MINIO_STORAGE_SIZE        | minio_storage_size      | --minio_storage_size      | Storage size for Minio (e.g., 15Gi)                                                                                                                                                      |
| STORAGE_PROVIDER          | storage_provider        | --storage_provider        | Storage provider to use, either `minio` (default) or `aws`                                                                                                                               |
| ASSESSMENT_ID             | assessment_id           | --assessment_id           | An ID for the assessment                                                                                                                                                                 |
| NEMESIS_HTTP_SERVER       | nemesis_http_server     | --nemesis_http_server     | The public HTTP server of the Nemesis server (for link creation). The port used here must match the port of the ingress-nginx-controller service in skaffold.yaml (port 8080 by default) |
| LOG_LEVEL                 | log_level               | --log_level               | (optional) Python logging level. Possible values: DEBUG, INFO, WARNING, ERROR, CRITICAL                                                                                                  |
| DATA_EXPIRATION_DAYS      | data_expiration_days    | --data_expiration_days    | The number of days to set for data expiration (default 100)                                                                                                                              |
| DISABLE_SLACK_ALERTING    | disable_slack_alerting  | --disable_slack_alerting  | Should slack alerting be disabled? Possible values: True/False                                                                                                                           |
| SLACK_CHANNEL             | slack_channel           | --slack_channel           | (optional) A Slack channel name for alerting, including the '#' (e.g., #nemesis)                                                                                                         |
| SLACK_WEBHOOK             | slack_webhook           | --slack_webhook           | (optional) A Slack webhook for alerting                                                                                                                                                  |
| BASIC_AUTH_USER           | basic_auth_user         | --basic_auth_user         | The username for basic auth to the Nemesis endpoint (default: nemesis)                                                                                                                   |
| BASIC_AUTH_PASSWORD       | basic_auth_password     | --basic_auth_password     | The basic auth password for the Nemesis  endpoit(default: random 24 characters)                                                                                                          |
| DASHBOARD_USER            | dashboard_user          | --dashboard_user          | The username for the main Nemesis dashboard                                                                                                                                              |
| DASHBOARD_PASSWORD        | dashboard_password      | --dashboard_password      | The password for the main Nemesis dashboard (default: random 24 characters)                                                                                                              |
| ELASTICSEARCH_USER        | elasticsearch_user      | --elasticsearch_user      | The username for elasticsearch/kibana (default: nemesis)                                                                                                                                 |
| ELASTICSEARCH_PASSWORD    | elasticsearch_password  | --elasticsearch_password  | The password for elasticsearch/kibana (default: random 24 characters)                                                                                                                    |
| GRAFANA_USER              | grafana_user            | --grafana_user            | The user for Grafana auth (default: nemesis)                                                                                                                                             |
| GRAFANA_PASSWORD          | grafana_password        | --grafana_password        | The password for Grafana auth (default: random 24 characters)                                                                                                                            |
| PGADMIN_EMAIL             | pgadmin_email           | --pgadmin_email           | "user@domain.local" email address to use to log into PgAmin (default: nemesis@nemesis.com)                                                                                               |
| PGADMIN_PASSWORD          | pgadmin_password        | --pgadmin_password        | The password for PgAmin (default: random 24 characters)                                                                                                                                  |
| POSTGRES_USER             | postgres_user           | --postgres_user           | The user for Postgres (default: nemesis)                                                                                                                                                 |
| POSTGRES_PASSWORD         | postgres_password       | --postgres_password       | The password for Postgres (default: random 24 characters)                                                                                                                                |
| RABBITMQ_ADMIN_USER       | rabbitmq_admin_user     | --rabbitmq_admin_user     | Username for the RabbitMQ interface (default: nemesis)                                                                                                                                   |
| RABBITMQ_ADMIN_PASSWORD   | rabbitmq_admin_password | --rabbitmq_admin_password | Password for the RabbitMQ interface (default: random 24 characters)                                                                                                                      |
| RABBITMQ_ERLANG_COOKIE    | rabbitmq_erlang_cookie  | --rabbitmq_erlang_cookie  | Password to allow RabbitMQ nodes to communicate (default: random 24 characters)                                                                                                          |

# Example: Specifying Nemesis options using the CLI arguments
The following configures Nemesis using CLI arguments, setting all services to use the same username and password. In this case `192.168.230.42` is the IP address the VM running minikube.
```
python3 nemesis-cli.py \
    --assessment_id ASSESS-TEST \
    --nemesis_http_server http://192.168.230.42:8080/ \
    --disable_slack_alerting True \
    --basic_auth_password PASSWORD \
    --basic_auth_user nemesis \
    --elasticsearch_user nemesis \
    --elasticsearch_password PASSWORD \
    --grafana_user nemesis \
    --grafana_password PASSWORD \
    --pgadmin_email nemesis@nemesis.local \
    --pgadmin_password PASSWORD \
    --postgres_user nemesis \
    --postgres_password PASSWORD \
    --log_level DEBUG \
    --rabbitmq_admin_user nemesis \
    --rabbitmq_admin_password PASSWORD \
    --dashboard_user nemesis \
    --dashboard_password PASSWORD
```