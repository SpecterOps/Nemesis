# Docker Desktop with Kubernetes

Using Docker Desktop for installing Nemesis is great for development and testing, but is not the best option for non-local installations.

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

2. [Enable Kubernetes in Docker Desktop](https://docs.docker.com/desktop/kubernetes/)

3. Install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)

Linux:
```bash
# Download kubectl binary
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
# Install kubectl to /usr/local/bin
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

Windows (winget)
```bash
winget install Kubernetes.kubectl
```

4. Install [Helm](https://helm.sh/docs/intro/install/)

Linux (apt):
```bash
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```

Windows (winget):
```bash
winget install Helm.Helm
```

5. Import Helm repositories for dependent services

**Purpose**: Nemesis depends on containers in different repositories

```bash
# Add Bitnami repository
helm repo add bitnami https://charts.bitnami.com/bitnami
```

6. Start Nemesis Quickstart

    This create secrets that are necessary for Nemesis to run.

    Run `helm install --repo https://specterops.github.io/Nemesis/ nemesis-quickstart quickstart`

    If you want to edit any of the password values for Nemesis, edit them in [values.yaml](../helm/quickstart/values.yaml).

    ```
    helm show values --repo https://specterops.github.io/Nemesis/ nemesis > quickstart-values.yaml
    # Edit values.yaml as you need
    helm install --repo https://specterops.github.io/Nemesis/ nemesis-quickstart quickstart -f quickstart-values.yaml
    ```

7. Install Traefik and eck-operator

**Purpose**: Helm dependencies can't put resources in other namespaces (`kube-system` and `elastic-system`), so we must install these separately.

```bash
helm install traefik traefik --repo https://traefik.github.io/charts --namespace kube-system
# Install ElasticSearch operator to manage "default" namespace. The managedNamespaces field will need to be configured if you want to install Nemesis to a namespace not "default"
helm install elastic-operator eck-operator --repo https://helm.elastic.co --namespace elastic-system --create-namespace --set managedNamespaces='{default}'
```