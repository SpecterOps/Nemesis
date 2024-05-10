#!/bin/bash

sudo pwd &> /dev/null

if ! command -v curl &> /dev/null; then
    echo -e "[*] curl could not be found, attempting to install...\n"
    sudo apt-get update
    sudo apt-get install curl -y
fi

clear -x

# Step 1: Install k3s
echo -e "\n[*] Installing k3s...\n"
curl -sfL https://get.k3s.io | sh -
mkdir -p ~/.kube && sudo k3s kubectl config view --raw > ~/.kube/config
chmod 600 ~/.kube/config
export KUBECONFIG=~/.kube/config

# Step 2: Install Helm
echo -e "\n[*] Installing Helm...\n"
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sleep 10
sudo apt-get install helm

# Step 3: Install Dependencies with Helm
echo -e "\n[*] Installing Dependencies with Helm...\n"
helm install elastic-operator eck-operator --repo https://helm.elastic.co --namespace elastic-system --create-namespace --set managedNamespaces='{default}'

clear -x
echo -e "\n[*] Nemesis k3s prereqs installed."
echo -e "[*] Install Nemesis with:\n"
echo -e "\thelm install --repo https://specterops.github.io/Nemesis/ nemesis-quickstart quickstart"
echo -e "\thelm install --repo https://specterops.github.io/Nemesis/ nemesis nemesis --timeout '45m' --set operation.nemesisHttpServer="https://\<IP\>:443/"\n"
