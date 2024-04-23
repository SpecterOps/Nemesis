# Requirements

## Table of Contents

1. [Table of Contents](#table-of-contents)
1. [VM Hardware Requirements](#vm-hardware-requirements)
2. [Software Requirements](#software-requirements)
    1. [K3s](#k3s)
    2. [Docker Desktop](#docker-desktop-with-kubernetes)
    3. [Minikube](#minikube)

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

We support installing Nemesis in either [Docker Desktop](#docker-desktop-with-kubernetes) or [Minikube](#minikube).

**The following requirements need to be installed:**

### K3s

Before installing k3s, you must have Docker installed on your system as it is a prerequisite for running containerized applications. Follow the Docker installation guide for your specific operating system at the official Docker documentation: [Install Docker Engine](https://docs.docker.com/engine/install/).

#### Install k3s

k3s is a lightweight Kubernetes distribution that simplifies the deployment and management of Kubernetes clusters. To install k3s without the Traefik ingress controller (as we will be using ingress-nginx), run the following command:

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

