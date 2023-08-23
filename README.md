<p align="center">
    <img src="img/nemesis_white.png" alt="Nemesis" style="width: 800px;" />
</p>
<hr />

<p align="center">
<img src="https://img.shields.io/badge/version-0.1.0a-blue" alt="version 0.1.0a"/>
<a href="https://join.slack.com/t/bloodhoundhq/shared_invite/zt-1tgq6ojd2-ixpx5nz9Wjtbhc3i8AVAWw">
    <img src="https://img.shields.io/badge/Slack-%23nemesis—chat-blueviolet?logo=slack" alt="Slack"/>
</a>
<a href="https://twitter.com/tifkin_">
    <img src="https://img.shields.io/twitter/follow/tifkin_?style=social"
      alt="@tifkin_ on Twitter"/></a>
<a href="https://twitter.com/harmj0y">
    <img src="https://img.shields.io/twitter/follow/harmj0y?style=social"
      alt="@harmj0y on Twitter"/></a>
<a href="https://twitter.com/0xdab0">
    <img src="https://img.shields.io/twitter/follow/0xdab0?style=social"
      alt="@0xdab0 on Twitter"/></a>
<a href="https://github.com/specterops#nemesis">
    <img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json&style=flat"
      alt="Sponsored by SpecterOps"/>
</a>
</p>
<hr />


# Overview

Nemesis is an offensive data enrichment pipeline and operator support system.

Built on Kubernetes with scale in mind, our goal with Nemesis was to create a centralized data processing platform that ingests data produced during offensive security assessments.

Nemesis aims to automate a number of repetitive tasks operators encounter on engagements, empower operators’ analytic capabilities and collective knowledge, and create structured and unstructured data stores of as much operational data as possible to help guide future research and facilitate offensive data analysis.

# Setup

1. Ensure the hardware/software requisites are met and configuration values are completed [as described here in the setup](./docs/setup.md)

2. Run `python3 nemesis_cli.py` and follow any prompts.

# Running

In the root directory of the repo, use skaffold to start everything:
```
skaffold run  --port-forward
```

Run `skaffold delete` to remove running pods.

The ingress port for Nemesis is **8080**, which routes access for all services. To change this port, in `./skaffold.yaml` modify the `localPort` value under the `portForward-ingress` configuration section.

The only other publicly forwarded port is **9001** if minio is used for storage (the default).

## Changing Persistent Storage

Elasticsearch, PostgreSQL, and Minio (if using instead of AWS S3) have persistent storage volumes in the cluster.

### Storage Backend

By default Minio will be used for storage. If `storage_provider=s3` is set via any config option, AWS S3 storage is used in conjunction with KMS for encryption. If this is the case, the `aws_*` config variables need to be completed, otherwise these values are ignored.

### Elasticsearch

The default storage size is 20Gi. To change this, modify the *two* `storage: 20Gi` entries under the **PersistentVolume** and **PersistentVolumeClaim** sections in ./kubernetes/elastic/elasticsearch.yaml

### PostgreSQL

The default storage size is 15Gi. To change this, modify the *two* `storage: 15Gi` entries under the **PersistentVolume** and **PersistentVolumeClaim** sections in ./kubernetes/postgres/deployment.yaml

### Minio

If using Minio (instead of AWS S3) the default storage size is `30Gi`. To change this, modify the **minio_storage_size** value in the nemesis.config file or cli argument.

## Troubleshooting Start

If you encounter an error along the lines of `deployment/gotenberg failed. Error: container gotenberg is waiting to start: gotenberg/gotenberg:7.7.0 can't be pulled.`, run `minikube ssh` and `docker pull X` where "X is the container pull that timed out (e.g., "gotenberg/gotenberg:7.7.0" in the previous example).

If the containers aren't able to reach the Internet or resolve addresses, add the following to `/etc/docker/daemon.json` and restart Docker with `sudo service docker restart`:
```
{
    "dns": ["8.8.8.8"]
}
```

# Usage

Browsing to `http://<NEMESIS_IP>:8080/` will display the main service routes. Operators' main interaction with Nemesis data will usually be the `/dashboard/` and `/kibana/` endpoints (and possibly `/pgadmin/`). See the **Exposed services** subsection below for credential details for each.

The main Nemesis dashboard allows for uploading files for manual processing, otherwise see the **C2 Connectors** subsection below.

## C2 Connectors

In order for Nemesis to perform data enrichment, data first needs to be ingested into the platform. The `./cmd/connectors/` folder contains the following connectors for various C2 platforms:

- Cobalt Strike
- Metasploit
- Mythic
- OST Stage1
- Sliver

See each applicable subfolder for more information on configuration.

***Note: not all connectors have the same level of completeness! We intended to show the range of connectors possible, but there is not yet feature parity.***

## Exposed services

All services are exposed through a single HTTP endpoint (defined in the NEMESIS_HTTP_SERVER environment variable) which is protected by HTTP basic auth defined by `BASIC_AUTH_USER:BASIC_AUTH_PASSWORD`.

To see a basic landing page with exposed services, go to http NEMESIS_HTTP_SERVER endpoint root. The routes and corresponding services are:

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


# Contributing / Development Environment Setup
See [development.md](./docs/development.md)


# Acknowledgments

Nemesis is built on large chunk of other people's work. Throughout the codebase we've provided citations, references, and applicable licenses for anything used or adapted from public sources. If we're forgotten proper credit anywhere, please let us know or submit a pull request!

We also want to acknowledge Evan McBroom, Hope Walker, and Carlo Alcantara from SpecterOps for their help with the initial Nemesis concept and amazing feedback throughout the development process.
