# Requirements

## Table of Contents

1. [Table of Contents](#table-of-contents)
1. [VM Hardware Requirements](#vm-hardware-requirements)
2. [Software Requirements](#software-requirements)
    1. [K3s](#k3s)

## VM Hardware Requirements
We have only tested on machines with the the following specs. All other configurations are not officially supported.

 * OS: Debian 11 LTS or Debian 11 on the Windows Subsystem for Linux (WSL).
 * 4 processors
 * 16 GB RAM
 * 100 GB disk

You could probably do 3 processors and 10 GB RAM, just might need to change how many CPUs and how much memory you give to minikube (and then cross your fingers you don't get OOMErrors from Kubernetes :P)

Additionally, only x64 architecture has been tested and is supported. ARM platforms (e.g., Mac devives with M* chips) are not currently supported but we intend to support these in the future.

**Do not install the following requirements as root! Minikube is particular does not like to be run as root.**

## Software Requirements

K3s is the only officially supported way to install Nemesis. Installation instructions for [Docker Desktop](requirements_docker_desktop.md) and [Minikube](requirements_minikube.md) do exist but may not be up to date.

**The following requirements need to be installed:**

### K3s

Before installing k3s, you must have Docker installed on your system as it is a prerequisite for running containerized applications. Follow the Docker installation guide for your specific operating system at the official Docker documentation: [Install Docker Engine](https://docs.docker.com/engine/install/).

#### Install k3s

k3s is a lightweight Kubernetes distribution that simplifies the deployment and management of Kubernetes clusters. Install k3s with the following command:

```bash
curl -sfL https://get.k3s.io | sh -
```

After installing k3s, modify your kubeconfig to use the k3s Kubernetes configuration with the following commands:

```bash
export KUBECONFIG=~/.kube/config
mkdir ~/.kube 2> /dev/null
sudo k3s kubectl config view --raw > "$KUBECONFIG"
chmod 600 "$KUBECONFIG"
```

#### Install Helm

Follow the Helm installation guide for your specific operating system: [Installing Helm](https://helm.sh/docs/intro/install/).

The installation instructions for Debian are replicated here:

```bash
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```

#### Install Dependencies

Install the Elastic operator with the following Helm command to manage Elasticsearch in the `default` namespace:

```bash
helm install elastic-operator eck-operator --repo https://helm.elastic.co --namespace elastic-system --create-namespace --set managedNamespaces='{default}'
```

#### Validate Installation

To ensure you're ready for the next step, run the command below and ensure a deployment exists for "traefik" and "elastic-operator."

```bash
$ helm ls -A
NAME                    NAMESPACE       REVISION        UPDATED                                 STATUS          CHART                           APP VERSION
elastic-operator        elastic-system  1               2024-04-22 10:42:02.9517585 -0400 EDT   deployed        eck-operator-2.12.1             2.12.1
traefik                 kube-system     1               2024-04-19 17:56:18.401408836 +0000 UTC deployed        traefik-25.0.2+up25.0.0         v2.10.5
traefik-crd             kube-system     1               2024-04-19 17:56:17.382691893 +0000 UTC deployed        traefik-crd-25.0.2+up25.0.0     v2.10.5
```