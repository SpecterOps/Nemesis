# Developer Requirements

## VM Hardware Requirements

The hardware requirements are the same as what's listed in [Hardware Requirements](requirements.md#vm-hardware-requirements).

## Software Requirements

K3s is the only officially supported way to install Nemesis. Installation instructions for [Docker Desktop](requirements_docker_desktop.md) and [Minikube](requirements_minikube.md) do exist but may not be up to date.

### Install Docker

Install Docker by following the [official Docker installation guide](https://docs.docker.com/engine/install/). The installation instructions for Debian are replicated below:

```bash
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt-get remove $pkg; done

sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Install K3s

Install K3s with [cri-dockerd](https://github.com/Mirantis/cri-dockerd) to allow K3s to use Docker to deploy containers. This allows Skaffold and Nemesis scripts to work.

k3s is a lightweight Kubernetes distribution that simplifies the deployment and management of Kubernetes clusters.
Install k3s with the following command:

```bash
curl -sfL https://get.k3s.io | sh - --docker
```

After installing k3s, modify your kubeconfig to use the k3s Kubernetes configuration with the following commands:

```bash
export KUBECONFIG=~/.kube/config
mkdir ~/.kube 2> /dev/null
sudo k3s kubectl config view --raw > "$KUBECONFIG"
chmod 600 "$KUBECONFIG"
```

### Install Helm

Follow the Helm installation guide for your specific operating system: [Installing Helm](https://helm.sh/docs/intro/install/).

The installation instructions for Debian are replicated here:

```bash
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```

### Install Dependencies

Install the Elastic operator with the following Helm command to manage Elasticsearch in the `default` namespace:

```bash
helm install elastic-operator eck-operator --repo https://helm.elastic.co --namespace elastic-system --create-namespace --set managedNamespaces='{default}'
```

### Validate Installation

To ensure you're ready for the next step, run the command below and ensure a deployment exists for "traefik" and "elastic-operator."

```bash
$ helm ls -A
NAME                    NAMESPACE       REVISION        UPDATED                                 STATUS          CHART                           APP VERSION
elastic-operator        elastic-system  1               2024-04-22 10:42:02.9517585 -0400 EDT   deployed        eck-operator-2.12.1             2.12.1
traefik                 kube-system     1               2024-04-19 17:56:18.401408836 +0000 UTC deployed        traefik-25.0.2+up25.0.0         v2.10.5
traefik-crd             kube-system     1               2024-04-19 17:56:17.382691893 +0000 UTC deployed        traefik-crd-25.0.2+up25.0.0     v2.10.5
```