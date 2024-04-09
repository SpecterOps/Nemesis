# Installing Nemesis on k3s

This guide covers setting up Nemesis on a k3s cluster and exposes the ingress-nginx ports to access Nemesis externally

## Install Docker

Before installing k3s, you must have Docker installed on your system as it is a prerequisite for running containerized applications. Follow the Docker installation guide for your specific operating system at the official Docker documentation: [Install Docker Engine](https://docs.docker.com/engine/install/).


## Install k3s

k3s is a lightweight Kubernetes distribution that simplifies the deployment and management of Kubernetes clusters. To install k3s without the Traefik ingress controller (as we will be using ingress-nginx), run the following command:

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable traefik" sh -s -
```

After installing k3s, modify your kubeconfig to use the k3s Kubernetes configuration with the following commands:

```bash
export KUBECONFIG=~/.kube/config
mkdir ~/.kube 2> /dev/null
sudo k3s kubectl config view --raw > "$KUBECONFIG"
chmod 600 "$KUBECONFIG"
```

## Install Helm

Follow the Helm installation guide for your specific operating system: [Installing Helm](https://helm.sh/docs/intro/install/).

## Install Nemesis Prerequisites

### Quickstart

The quickstart Helm chart sets up necessary secrets and configurations for Nemesis. To install the quickstart chart from the SpecterOps repository, use the following command:

```bash
helm install --repo https://specterops.github.io/Nemesis/ nemesis-quickstart quickstart
```

If you need to configure custom values for the quickstart chart, first download the default values:

```bash
helm show values nemesis/quickstart > values.yaml
```

After modifying values.yaml as needed, install the quickstart chart using your customized values:

```bash
helm install nemesis-quickstart nemesis/quickstart -f values.yaml
```

### Dependencies

Nemesis requires ingress-nginx for routing HTTP requests and the Elastic operator for managing Elasticsearch instances. Follow these steps to install these dependencies:

#### Ingress-NGINX

Add the ingress-nginx manifest file to `/var/lib/rancher/k3s/server/manifests/nginx.yaml` with the configuration provided below:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ingress-nginx
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: ingress-nginx
  namespace: kube-system
spec:
  chart: ingress-nginx
  repo: https://kubernetes.github.io/ingress-nginx
  targetNamespace: ingress-nginx
  version: v4.0.19
  set:
  valuesContent: |-
    fullnameOverride: ingress-nginx
    prometheus:
      port: 9113
    tcp:
      5044: 'default/nemesis-ls-beats:5044'
    controller:
      kind: DaemonSet
      dnsPolicy: ClusterFirstWithHostNet
      watchIngressWithoutClass: true
      allowSnippetAnnotations: false
      hostNetwork: true
      hostPort:
        enabled: true
      publishService:
        enabled: false
      service:
        enabled: false
      extraArgs:
        default-ssl-certificate: default/nemesis-cert
      config:
        proxy-body-size: 5000m
```

K3s will periodically enumerate this folder for new manifests and automatically apply them. You can check if the Helm chart has been applied by running:

```bash
helm ls -A | grep ingress-nginx
```

#### Elastic Operator

Install the Elastic operator with the following Helm command to manage Elasticsearch in the `default` namespace:

```bash
helm install elastic-operator eck-operator --repo https://helm.elastic.co --namespace elastic-system --create-namespace --set managedNamespaces='{default}'
```


## Install Nemesis

With the prerequisites in place, you can now install Nemesis. Use the following command to install Nemesis using the SpecterOps Helm repository. This command includes a timeout parameter to ensure the installation process allows enough time to complete:

```bash
helm install --repo https://specterops.github.io/Nemesis/ nemesis nemesis --timeout '45m'
```

## Verify Installation

Use the following bash oneliner to get the basic auth secrets and ensure the Nemesis home page is reachable:

```bash
$ curl -u $(kubectl get secret operation-creds -o jsonpath='{.data.basic-auth-user}' | base64 --decode):$(kubectl get secret operation-creds -o jsonpath='{.data.basic-auth-password}' | base64 --decode) http://127.0.0.1

<html>
    <head>
        <title>Nemesis Services</title>
    </head>
    <body>
        <h1>Nemesis Services</h1>

        <h2>Main Services</h2>
        <a href="/dashboard/" target="_blank"">Dashboard</a><br>
...
```

