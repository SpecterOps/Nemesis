# Nemesis Installation and Setup
1. Ensure the [requisite software/hardware is installed](./requirements.md).

2. Run `python3 nemesis-cli.py` to configure Nemesis's kubernetes environment. Examples and detailed usage info [can be found here](./nemesis-cli.md).

3. Start all of Nemesis's services with `skaffold run --port-forward`.

   Once running, browsing `http://<NEMESIS_IP>:8080/` (or whatever you specified in the `nemesis_http_server` nemesis-cli option) will display a set of links to Nemesis services. Operators primarily use the Dashboard which allows them to upload files and triage ingested/processed data.

4. [Ingest data into Nemesis.](#data-ingestion)

# Data Ingestion
Once Nemesis is running, data first needs to be ingested into the platform. Ingestion into Nemesis can occur in muliple ways, including
* [Auto-ingesting data from C2 platorms.](#nemesis-c2-connector-setup)
* Manually uploading files on the "File Upload" page in the Nemesis's Dashboard UI.
* Using the [submit_to_nemesis](./submit_to_nemesis.md) CLI tool to submit files.
* Writing custom tools to interact with Nemesis's API.

## Nemesis C2 Connector Setup
Nemesis includes connectors for various C2 platorms. The connectors hook into the C2 platforms and transfer data automatically into Nemesis. The `./cmd/connectors/` folder contains the following C2 connectors:

- [Cobalt Strike](../cmd/connectors/cobaltstrike-nemesis-connector/README.md)
- [Mythic](../cmd/connectors/mythic-connector/README.md)
- [Sliver](../cmd/connectors/sliver-connector/README.md)
- [OST Stage1](../cmd/connectors/stage1-connector/README.md)
- [Metasploit](../cmd/connectors/metasploit-connector/README.md)
- [Chrome Extension](../cmd/connectors/chrome-extension/README.md)

***Note: not all connectors have the same level of completeness! We intended to show the range of connectors possible, but there is not yet feature parity.***

If you'd like to ingest data from another platform, see the documentation for [adding a new connector](./new_connector.md).

# Nemesis Service Endpoints

All Nemesis services are exposed through a single HTTP endpoint (defined in the NEMESIS_HTTP_SERVER environment variable) protected by HTTP basic auth credentials configured through the `BASIC_AUTH_USER` and `BASIC_AUTH_PASSWORD` settings.

To see a basic landing page with exposed services, go to http `NEMESIS_HTTP_SERVER` endpoint root. The routes and corresponding services are:

| Service      | Route             | Username            | Password                |
| ------------ | ----------------- | ------------------- | ----------------------- |
| dashboard    | /dashboard/       | DASHBOARD_USER      | DASHBOARD_PASSWORD      |
| kibana       | /kibana/          | ELASTICSEARCH_USER  | ELASTICSEARCH_PASSWORD  |
| pgadmin      | /pgadmin/         | PGADMIN_EMAIL       | PGADMIN_PASSWORD        |
| rabbitmq     | /rabbitmq/        | RABBITMQ_ADMIN_USER | RABBITMQ_ADMIN_PASSWORD |
| alertmanager | /alertmanager/    | N/A                 | N/A                     |
| grafana      | /grafana/         | GRAFANA_USER        | GRAFANA_PASSWORD        |
| prometheus   | /prometheus/graph | N/A                 | N/A                     |
| web-api      | /api/             | N/A                 | N/A                     |
| elastic      | /elastic/         | ELASTICSEARCH_USER  | ELASTICSEARCH_PASSWORD  |
| yara         | /yara/            | N/A                 | N/A                     |
| crack-list   | /crack-list/      | N/A                 | N/A                     |

# (Optional) Changing Persistent File Storage

Elasticsearch, PostgreSQL, and Minio (if using instead of AWS S3) have persistent storage volumes in the cluster.

## File Storage Backend

By default, Nemesis uses Minio for file storage with a default storage size of `30Gi`. To change the size, modify the **minio_storage_size** value in the nemesis.config file or CLI argument.

Nemesis can use AWS S3 (in conjunction with KMS for file encryption) for file storage by setting the `storage_provider` to `s3` when running `nemesis-cli.py`.  When S3 file storage is configured, the `aws_*` nemesis-cli.py config variables need to be completed.

## Elasticsearch

The default storage size is 20Gi. To change this, modify the *two* `storage: 20Gi` entries under the **PersistentVolume** and **PersistentVolumeClaim** sections in ./kubernetes/elastic/elasticsearch.yaml

## PostgreSQL

The default storage size is 15Gi. To change this, modify the *two* `storage: 15Gi` entries under the **PersistentVolume** and **PersistentVolumeClaim** sections in ./kubernetes/postgres/deployment.yaml



# (Optional) Chainge Nemesis's Listening Port
The ingress port for Nemesis is **8080**, which routes access for all services. To change this port, in `./skaffold.yaml` modify the `localPort` value under the `portForward-ingress` configuration section (if you change this, you must update nemesis-cli.py's `nemesis_http_server` option).

The only other publicly forwarded port is **9001** if minio is used for storage (the default).

Underneath, Skaffold manages all of Nemesis's port forwards using `kubectl`. If you'd like `kubectl` to be able to bind to lower ports without being root, you can run the following:
```bash
sudo setcap CAP_NET_BIND_SERVICE=+eip /path/to/kubectl
```

# (Optional) Deleting Running Pods
Run `skaffold delete` at the root of the repo to remove running pods. There currently is not a way to remove all the Kubernetes objects created by `nemesis-cli.py` without deleting the cluster (e.g., `minikube delete`).

# Troubleshooting, Common Errors, and Support
## "CONTAINER can't be pulled" error
When running skaffold, you may encounter an error stating:
> deployment/______ failed. Error: container _____ is waiting to start: _______ can't be pulled

This error usually occurs when on a slower internet connection and occurs because skaffold has to pull down a large docker image and eventually times out due to the download taking too long. This most commonly occurs with the gotenberg image, manifesting with this error:
> deployment/gotenberg failed. Error: container gotenberg is waiting to start: gotenberg/gotenberg:7.7.0 can't be pulled.

Two solutions:
* Run `minikube ssh docker pull CONTAINER` to manually pull an individual docker image into minikube.
* In the root of the repo run `./scripts/pull_images.sh`. This will pull all Nemesis docker images into minikube w/o using skaffold.

## Troubleshooting Minikube's Internet/DNS
The easiest way to troubleshoot internet/DNS issues is to use `minikube ssh` to get a terminal in the minikube host. From there, you can test connectivity in a variety of ways:
```
# Test internet connectivity
ping -c 1 1.1.1.1

# Test DNS
nslookup google.com

# Test docker image pulling is working
docker pull debian:11
```

If minikube can connect to the internet but DNS isn't working, add the following to `/etc/docker/daemon.json` and restart Docker with `sudo service docker restart`:
```
{
    "dns": ["8.8.8.8"]
}
```

## Freshly Install Nemesis
If you want to start fresh again you can run the following general steps:
```
minikube delete   # delete your current cluster
minikube start    # start up minikube again

python3 nemesis-cli.py  # Setup Nemesis configuration again

./scripts/pull_images.sh  # Avoid any potential skaffold timeouts that may occur from image pulling taking a long time
skaffold build            # Manually build everything

skaffold run  --port-forward  # Kick things off
```

## Need additional help?
Please [file an issue](https://github.com/SpecterOps/Nemesis/issues) or feel free to ask questions in the [#nemesis-chat channel](https://bloodhoundhq.slack.com/archives/C05KN15CCGP) in the Bloodhound Slack ([click here to join](https://ghst.ly/BHSlack)).