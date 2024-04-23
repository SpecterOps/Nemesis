# Quickstart Guide

Here's a quickstart guide to setting up the Nemesis platform using k3s and Helm on Debian 11. This guide will start a Nemesis server running locally and accessible through "https://127.0.0.1". If this does not fit your installation need, see the full [setup guide](setup.md).

### Prerequisites
Ensure your machine meets the following requirements:
- **OS**: Debian 11 LTS
- **Processors**: 4 cores (3 can work with adjustments)
- **Memory**: 16 GB RAM (minimum of 10 GB for reduced performance)
- **Disk Space**: 100 GB
- **Architecture**: x64 only

### Step 1: Install Docker
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


### Step 2: Install k3s

Execute the following commands to install [k3s](https://docs.k3s.io/quick-start):

```bash
curl -sfL https://get.k3s.io | sh -
mkdir -p ~/.kube && sudo k3s kubectl config view --raw > ~/.kube/config
chmod 600 ~/.kube/config
export KUBECONFIG=~/.kube/config
```


### Step 3: Install Helm

Install [Helm](https://helm.sh/docs/intro/install/):

```bash
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```


### Step 4: Install Dependencies

Install dependencies using Helm:

```bash
helm install elastic-operator eck-operator --repo https://helm.elastic.co --namespace elastic-system --create-namespace --set managedNamespaces='{default}'
```


### Step 5: Install the `quickstart` Chart

Deploy the `quickstart` Helm chart to configure secrets:

```bash
helm install --repo https://specterops.github.io/Nemesis/ nemesis-quickstart quickstart
```

### Step 6: Install `nemesis`

Deploy the main Nemesis services:

```bash
helm install --repo https://specterops.github.io/Nemesis/ nemesis nemesis --timeout '45m'
```


### Step 7: Get basic-auth Secret

Retrieve the basic authentication credentials to access the dashboard:

```bash
export BASIC_AUTH_USER=$(kubectl get secret basic-auth -o jsonpath="{.data.username}" | base64 -d)
export BASIC_AUTH_PASSWORD=$(kubectl get secret basic-auth -o jsonpath="{.data.password}" | base64 -d)
echo "${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD}"
```

### Step 8: Logging into the Dashboard

Once all installations and configurations are complete, open a web browser and go to:

```
https://127.0.0.1
```

Enter the basic authentication credentials you retrieved earlier to access the Nemesis dashboard. Use the following credentials:
- **Username**: The value stored in `${BASIC_AUTH_USER}`
- **Password**: The value stored in `${BASIC_AUTH_PASSWORD}`