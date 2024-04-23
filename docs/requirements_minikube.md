# MiniKube

## Docker and docker-compose

**Purpose:** Skaffold uses docker to build container images

 Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) on your machine or [install docker/docker-compose with the following commands:](https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script):
```bash
sudo apt-get update
sudo apt-get install -y curl
sudo mkdir /etc/apt/keyrings/ 2>/dev/null
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

sudo apt-get install -y docker-compose

# Allow your user to run docker w/o being root, and then logout and back in
sudo usermod -aG docker <user>
```
**Validation:** `docker ps` should work as a non-root user.

## Kubectl

**Purpose:** CLI tool to interact with Kubernetes.
Instructions found here: https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/

**Validation:** `kubectl` should display the tool's usage. Once a Kubernetes cluster is running/configured, `kubectl get pods -A` should show some kubernetes-related pods running.
</details>

## Kubernetes

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
* Run `minikube ssh` and then run `ping -c 1.1.1.1` to test internet connectivity and `nslookup google.com` to test DNS.


**Note 1 - (Optional) Authenticating to a docker registry**

Because Minikube's docker daemon runs on a different machine, you may want to configure it to authenticate to a docker registry (for example, to avoid [docker hub API limits](https://docs.docker.com/docker-hub/download-rate-limit/)). If you've authenticated to a docker registry on the minikube host machine (e.g., [using an access token with dockerhub](https://docs.docker.com/docker-hub/access-tokens/)), you add the credential to Minikube using the following command and it will pull images using that cred:

```bash
kubectl create secret generic regcred --from-file=.dockerconfigjson=$(realpath ~/.docker/config.json) --type=kubernetes.io/dockerconfigjson
```

**Note 2 - (Optional) Minikube's docker daemon:**

Minikube creates a Linux VM that has its own docker daemon inside of it. To configure your host OS's docker CLI to use minikube's docker daemon, [see the instructions here](https://skaffold.dev/docs/environment/local-cluster/#minikube-has-a-separate-docker-daemon).


## Helm

**Purpose:** Like a package manager, but for Kubernetes stuff.

[Link to Helm's installation instructions.](https://helm.sh/docs/intro/install/#from-apt-debianubuntu)

```bash
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install -y helm
```
**Validation:** `helm list` should work and not list any installed packages.

## Skaffold

**Purpose:** Development tool used to auto deploy containers to a Kubernetes cluster anytime the code changes.

***This is only needed if you're planning on doing Nemesis development!***

[Install Skaffold v2.7.1 with this command](https://github.com/GoogleContainerTools/skaffold/releases/tag/v2.7.1):
```
# For Linux x86_64 (amd64)
curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/v2.7.1/skaffold-linux-amd64 && chmod +x skaffold && sudo mv skaffold /usr/local/bin
```
Optional settings:
* Disable anonymous metrics collection:
```
skaffold config set --global collect-metrics false
```
* Disable the update check on each run (especially needed in offline installs) by setting the `SKAFFOLD_UPDATE_CHECK` to `false` before running skaffold. For example, you can add the following to your `~/.bashrc` file to disable the update check anytime your user account runs skaffold:
```
export SKAFFOLD_UPDATE_CHECK=false
```

**Validation:** Running `skaffold` should print skaffold's help.


## Required Kubernetes services

You will need to install two services in k8s before getting started. Helm makes this process very simple. If you already have an ElasticSearch cluster or an NGinx Ingress set up in the desired namespace, then you can configure them yourself. You can set them up from scratch with the process below:

```bash
# Add Bitnami repository
helm repo add bitnami https://charts.bitnami.com/bitnami
# Install Traefik ingress
helm install traefik traefik --repo https://traefik.github.io/charts --namespace kube-system
# Install ElasticSearch operator to manage "default" namespace. The managedNamespaces field will need to be configured if you desire to install Nemesis in a different namespace
helm install elastic-operator eck-operator --repo https://helm.elastic.co --namespace elastic-system --create-namespace --set managedNamespaces='{default}'
```
</details>