# VM Hardware Requirements
We have only tested on machines with the the following specs. All other configurations are not officially supported.

 * OS: Debian 11 LTS or Debian 11 on the Windows Subsystem for Linux(WSL).
 * 4 processors
 * 16 GB RAM
 * 100 GB disk

You could probably do 3 processors and 10 GB RAM, just might need to change how many CPUs and how much memory you give to minikube (and then cross your fingers you don't get OOMErrors from Kubernetes :P)

Additionally, only x64 architecture has been tested and is supported. ARM platforms (e.g., Mac devives with M* chips) are not currently supported but we intend to support these in the future.

**Do not install the following requirements as root! Minikube is particular does not like to be run as root.**

# Software Requirements
**The following requirements need to be installed:**

<details>
<summary>
Docker and docker-compose
</summary>

**Purpose:** Skaffold uses docker to build container images

 Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) on your machine or [install docker/docker-compose with the following commands:](https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script):
```bash
sudo apt-get update
sudo apt-get install curl
sudo mkdir /etc/apt/keyrings/ 2>/dev/null
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

sudo apt-get install docker-compose

# Allow your user to run docker w/o being root, and then logout and back in
sudo usermod -aG docker <user>
```
**Validation:** `docker ps` should work as a non-root user.
</details>

<details>
<summary>
Kubectl
</summary>

**Purpose:** CLI tool to interact with Kubernetes.
Instructions found here: https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
**Validation:** `kubectl` should display the tool's usage. Once a Kubernetes cluster is running/configured, `kubectl get pods -A` should show some kubernetes-related pods running.
</details>

<details>
<summary>
Kubernetes
</summary>

**Purpose:** Infrastructure for running/managing containerized application.

Install Minikube or enable Kubernetes on Docker Desktop. Install Minikube (at least v1.26.1) by running [the following commands](https://minikube.sigs.k8s.io/docs/start/):
```bash
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

Configure the cluster with at a minimum of 3 CPUs and 10Gb of memory:
```
minikube config set memory 12288
minikube config set cpus 3
```

Then start minikube (you'll need to run this each time the system boots as minikube does not run as a service):
```
minikube start
```
**Validation:**
* `minikube status` should show that the Kubernetes services are running
* `minikube version` should show at least a version greater than v1.26.1


**Note 1 - (Optional) Authenticating to a docker registry**

Because Minikube's docker daemon runs on a different machine, you may want to configure it to authenticate to a docker registry (for example, to avoid [docker hub API limits](https://docs.docker.com/docker-hub/download-rate-limit/)). If you've authenticated to a docker registry on your local machine (e.g., [using an access token with dockerhub](https://docs.docker.com/docker-hub/access-tokens/)), you add the credential to Minikube using the following command and it will pull images using that cred:

```bash
kubectl create secret generic regcred --from-file=.dockerconfigjson=$(realpath ~/.docker/config.json) --type=kubernetes.io/dockerconfigjson
```

**Note 2 - (Optional) Minikube's docker daemon:**

Minikube creates a Linux VM that has its own docker daemon inside of it. To configure your host OS's docker CLI to use minikube's docker daemon, [see the instructions here](https://skaffold.dev/docs/environment/local-cluster/#minikube-has-a-separate-docker-daemon).


</details>

<details>
<summary>
Helm
 </summary>

**Purpose:** Like a package manager, but for Kubernetes stuff.

[Link to Helm's installation instructions.](https://helm.sh/docs/intro/install/#from-apt-debianubuntu)

```bash
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```
**Validation:** `helm list` should work and not list any installed packages.
</details>

<details>
<summary>
Skaffold
</summary>

**Purpose:** Development tool used to auto deploy containers to a Kubernetes cluster anytime the code changes.

[Install Skaffold v1.39.2 with this command](https://github.com/GoogleContainerTools/skaffold/releases/tag/v1.39.2):
```
# For Linux x86_64 (amd64)
curl -Lo skaffold "https://storage.googleapis.com/skaffold/releases/v2.2.0/skaffold-linux-amd64" && chmod +x skaffold && sudo mv skaffold /usr/local/bin

# (Optional) Disable anonymous metrics collection
skaffold config set --global collect-metrics false

```
**Validation:** Running `skaffold` should print skaffold's help.
</details>

<details>
<summary>
Python, Pyenv, and Poetry
</summary>

## Install Pyenv
**Purpose:** Manages python environments in a sane way.

1. Install the [relevant prereqs specified by PyEnv](https://github.com/pyenv/pyenv/wiki#suggested-build-environment).
2. Installation:
```bash
curl https://pyenv.run | bash
```
3. After running the install script, add the following to `~/.bashrc`:
```bash
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
if command -v pyenv 1>/dev/null 2>&1; then
 eval "$(pyenv init --path)"
fi
eval "$(pyenv virtualenv-init -)"
```
4. Restart your shell
5. Install a version of Python and configure the version of Python to use globally on your machine
```bash
 pyenv install 3.11.2
 pyenv global 3.11.2
```

**Validation:** Running `python3 --version` should show version 3.11.2.

## Install Poetry
**Purpose:** Python package and dependency management tool.
```bash
python3 -c 'from urllib.request import urlopen; print(urlopen("https://install.python-poetry.org").read().decode())' | python3 -
```

Add the following to `~/.bashrc`:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

Restart your shell.

## Install Poetry Environment for Artifact Submission
**Purpose:** Install the Poetry environment for ./scripts/submit_to_nemesis.sh

`./scripts/submit_to_nemesis.sh` uses code from a Nemesis module that needs its Poetry environment installed first.

```
poetry -C ./cmd/enrichment/ install
```

</details>


# Setup Configuration

The `nemesis_cli.py` script can accept configuration values through (in descending order of precendence):
- Applicable environment variables
- A simple `nemesis.config` YAML file
- Command line arguments

If configuration values are not supplied and are not currently set in the kubectl instance, the script will prompt the user value input.

## Setup Variables

<details>
<summary>
Setup Variables
</summary>

| Env Variable              | `nemesis.config` entry  | cli argument              | Description                                                                                |
| ------------------------- | ----------------------- | ------------------------- | ------------------------------------------------------------------------------------------ |
| AWS_REGION                | aws_region              | --aws_region              | The region for the AWS S3 bucket/KMS key                                                   |
| AWS_BUCKET                | aws_bucket              | --aws_bucket              | The AWS S3 bucket name                                                                     |
| AWS_KMS_AWS_KMS_KEY_ALIAS | aws_kms_key_alias       | --aws_kms_key_alias       | The alias of the AWS KMS key                                                               |
| AWS_ACCESS_KEY_ID         | aws_access_key_id       | --aws_access_key_id       | The AWS access key ID                                                                      |
| AWS_SECRET_KEY            | aws_secret_key          | --aws_secret_key          | The AWS secret key                                                                         |
| MINIO_ROOT_USER           | minio_root_user         | --minio_root_user         | The username for Minio (it not using AWS)                                                  |
| MINIO_ROOT_PASSWORD       | minio_root_password     | --minio_root_password     | The password for Minio (it not using AWS)                                                  |
| MINIO_STORAGE_SIZE        | minio_storage_size      | --minio_storage_size      | Storage size for Minio (e.g., 15Gi)                                                        |
| STORAGE_PROVIDER          | storage_provider        | --storage_provider        | Storage provider to use, either `minio` (default) or `aws`                                 |
| ASSESSMENT_ID             | assessment_id           | --assessment_id           | An ID for the assessment                                                                   |
| NEMESIS_HTTP_SERVER       | nemesis_http_server     | --nemesis_http_server     | The public HTTP server of the Nemesis server (for link creation)                           |
| LOG_LEVEL                 | log_level               | --log_level               | (optional) Python logging level. Possible values: DEBUG, INFO, WARNING, ERROR, CRITICAL    |
| DATA_EXPIRATION_DAYS      | data_expiration_days    | --data_expiration_days    | The number of days to set for data expiration (default 100)                                |
| DISABLE_SLACK_ALERTING    | DISABLE_SLACK_ALERTING  | --disable_slack_alerting  | Should slack alerting be disabled? Possible values: True/False                             |
| SLACK_CHANNEL             | slack_channel           | --slack_channel           | (optional) A Slack channel name for alerting, including the '#' (e.g., #nemesis)           |
| SLACK_WEBHOOK             | slack_webhook           | --slack_webhook           | (optional) A Slack webhook for alerting                                                    |
| BASIC_AUTH_USER           | basic_auth_user         | --basic_auth_user         | The username for basic auth to the Nemesis endpoint (default: nemesis)                     |
| BASIC_AUTH_PASSWORD       | basic_auth_password     | --basic_auth_password     | The basic auth password for the Nemesis  endpoit(default: random 24 characters)            |
| DASHBOARD_USER            | dashboard_user          | --dashboard_user          | The username for the main Nemesis dashboard                                                |
| DASHBOARD_PASSWORD        | dashboard_password      | --dashboard_password      | The password for the main Nemesis dashboard (default: random 24 characters)                |
| ELASTICSEARCH_USER        | elasticsearch_user      | --elasticsearch_user      | The username for elasticsearch/kibana (default: nemesis)                                   |
| ELASTICSEARCH_PASSWORD    | elasticsearch_password  | --elasticsearch_password  | The password for elasticsearch/kibana (default: random 24 characters)                      |
| GRAFANA_USER              | grafana_user            | --grafana_user            | The user for Grafana auth (default: nemesis)                                               |
| GRAFANA_PASSWORD          | grafana_password        | --grafana_password        | The password for Grafana auth (default: random 24 characters)                              |
| PGADMIN_EMAIL             | pgadmin_email           | --pgadmin_email           | "user@domain.local" email address to use to log into PgAmin (default: nemesis@nemesis.com) |
| PGADMIN_PASSWORD          | pgadmin_password        | --pgadmin_password        | The password for PgAmin (default: random 24 characters)                                    |
| POSTGRES_USER             | postgres_user           | --postgres_user           | The user for Postgres (default: nemesis)                                                   |
| POSTGRES_PASSWORD         | postgres_password       | --postgres_password       | The password for Postgres (default: random 24 characters)                                  |
| RABBITMQ_ADMIN_USER       | rabbitmq_admin_user     | --rabbitmq_admin_user     | Username for the RabbitMQ interface (default: nemesis)                                     |
| RABBITMQ_ADMIN_PASSWORD   | rabbitmq_admin_password | --rabbitmq_admin_password | Password for the RabbitMQ interface (default: random 24 characters)                        |
| RABBITMQ_ERLANG_COOKIE    | rabbitmq_erlang_cookie  | --rabbitmq_erlang_cookie  | Password to allow RabbitMQ nodes to communicate (default: random 24 characters)            |

</details>
