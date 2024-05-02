# Nemesis Installation and Setup

1. Ensure the [requisite software/hardware is installed](requirements.md).

2. Run the [`quickstart` Helm chart](quickstart_chart.md) to configure Nemesis's services and secrets.

3. Deploy Nemesis's services by [using its Helm chart](nemesis_chart.md).

4. [Setup and access Nemesis](access_nemesis.md).

5. [Ingest data into Nemesis.](#data-ingestion)

If you run into any issues, please see [troubleshooting.md](troubleshooting.md) for common errors/issues.


## Data Ingestion

Once Nemesis is running, data first needs to be ingested into the platform. Ingestion into Nemesis can occur in muliple ways, including

* [Auto-ingesting data from C2 platorms.](#nemesis-c2-connector-setup)
* Manually uploading files on the "File Upload" page in the Nemesis's Dashboard UI.
* Using the [submit_to_nemesis](submit_to_nemesis.md) CLI tool to submit files.
* Writing custom tools to interact with [Nemesis's API](new_connector.md).


### Nemesis C2 Connector Setup

Nemesis includes connectors for various C2 platorms. The connectors hook into the C2 platforms and transfer data automatically into Nemesis. The `./cmd/connectors/` folder contains the following C2 connectors:

- [Cobalt Strike](https://github.com/SpecterOps/Nemesis/tree/main/cmd/connectors/cobaltstrike-nemesis-connector#readme)
- [Mythic](https://github.com/SpecterOps/Nemesis/tree/main/cmd/connectors/mythic-connector#readme)
- [Sliver](https://github.com/SpecterOps/Nemesis/tree/main/cmd/connectors/sliver-connector#readme)
- [OST Stage1](https://github.com/SpecterOps/Nemesis/tree/main/cmd/connectors/stage1-connector#readme)
- [Metasploit](https://github.com/SpecterOps/Nemesis/tree/main/cmd/connectors/metasploit-connector#readme)
- [Chrome Extension](https://github.com/SpecterOps/Nemesis/tree/main/cmd/connectors/chrome-extension#readme)

***Note: not all connectors have the same level of completeness! We intended to show the range of connectors possible, but there is not yet feature parity.***

If you'd like to ingest data from another platform, see the documentation for [adding a new connector](new_connector.md).


## Nemesis Service Endpoints

All Nemesis services are exposed through a single HTTP endpoint (defined in the NEMESIS_HTTP_SERVER environment variable) protected by HTTP basic auth credentials configured through the `BASIC_AUTH_USER` and `BASIC_AUTH_PASSWORD` settings.

To see a basic landing page with exposed services, go to http `NEMESIS_HTTP_SERVER` endpoint root. The routes and corresponding services are:

| Service         | Route             | Username            | Password                |
| --------------- | ----------------- | ------------------- | ----------------------- |
| dashboard       | /dashboard/       | DASHBOARD_USER      | DASHBOARD_PASSWORD      |
| kibana          | /kibana/          | ELASTICSEARCH_USER  | ELASTICSEARCH_PASSWORD  |
| Hasura          | /hasura/          | N/A                 | N/A                     |
| Nemesis web-api | /api/             | N/A                 | N/A                     |
| pgadmin         | /pgadmin/         | PGADMIN_EMAIL       | PGADMIN_PASSWORD        |
| rabbitmq        | /rabbitmq/        | RABBITMQ_ADMIN_USER | RABBITMQ_ADMIN_PASSWORD |
| alertmanager    | /alertmanager/    | N/A                 | N/A                     |
| grafana         | /grafana/         | GRAFANA_USER        | GRAFANA_PASSWORD        |
| prometheus      | /prometheus/graph | N/A                 | N/A                     |
| elastic         | /elastic/         | ELASTICSEARCH_USER  | ELASTICSEARCH_PASSWORD  |
| yara            | /yara/            | N/A                 | N/A                     |
| crack-list      | /crack-list/      | N/A                 | N/A                     |


## (Optional) Install logging and monitoring services by running the following:
```bash
helm install --repo https://specterops.github.io/Nemesis/ monitoring monitoring
```


## (Optional) Install Metrics Server
Metrics Server is available but not installed by default. Enable it with the following:

```bash
helm show values --repo https://specterops.github.io/Nemesis/ nemesis
```

Modify the value:

```yaml
metricsServer:
  enabled: true
```

If you have not installed Nemesis yet, see [Nemesis Chart](nemesis_chart.md) or upgrade the installation:

```bash
helm upgrade --repo https://specterops.github.io/Nemesis/ [chart name] nemesis
```


## (Optional) Changing Persistent File Storage

Elasticsearch, PostgreSQL, and Minio (if using instead of AWS S3) have persistent storage volumes in the cluster.


### File Storage Backend

Nemesis can use AWS S3 (in conjunction with KMS for file encryption) for file storage by modifying the `storage` setting in [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml) and configuring the `aws` block.

By default, Nemesis uses Minio for file storage with a default storage size of `30Gi`.
To change the size, modify the `minio.persistence.size` value in [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml) file.


### Elasticsearch

The default storage size is 20Gi. To change this, modify the `elasticsearch.storage` value in [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml).


### PostgreSQL

The default storage size is 20Gi. To change this, modify the `postgres.storage` value in [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml).


## (Optional) Change Nemesis's Listening Port

Create the `traefik-config.yaml` manifest with the following content:

```yaml
# /var/lib/rancher/k3s/server/manifests/traefik-config.yaml
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    ports:
      web:
        exposedPort: 8080
      websecure:
        exposedPort: 8443
```

## (Optional) Deleting Running Pods


### Using Helm
`helm uninstall nemesis && kubectl delete all --all -n default`


### Using Skaffold
`skaffold delete`


## (Optional) Running Helm local charts
If you do not want to run the Helm charts hosted on `https://specterops.github.io/Nemesis/`, you can run them locally. For example:
```bash
helm install nemesis-quickstart ./helm/quickstart
helm install nemesis ./helm/nemesis --timeout '45m'
helm install nemesis-monitoring ./helm/monitoring
```


## Troubleshooting, Common Errors, and Support

### Need additional help?
If you run into any issues, please see [troubleshooting.md](troubleshooting.md) for common errors/issues.

Otherwise, [file an issue](https://github.com/SpecterOps/Nemesis/issues) or feel free to ask questions in the [#nemesis-chat channel](https://bloodhoundhq.slack.com/archives/C05KN15CCGP) in the Bloodhound Slack ([click here to join](https://ghst.ly/BHSlack)).
