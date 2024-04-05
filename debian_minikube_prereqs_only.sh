#!/bin/bash

# Installs the prereqs needed to install Nemesis

# Install Docker
sudo apt-get update
sudo apt-get install -y curl
sudo mkdir /etc/apt/keyrings/ 2>/dev/null
curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
sudo sh /tmp/get-docker.sh
sudo apt install -y docker-compose
sudo usermod -aG docker $USER


# echo the next part of the script to a temp location so we can run with newgrp
cat << EOF > /tmp/setup_part_2.sh

# Install Kubectl
curl -LO "https://dl.k8s.io/release/\$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
minikube config set memory 12288
minikube config set cpus 3
minikube start

# Install Helm
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [arch=\$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install -y helm

# Install k8s prereqs
# Add Elastic repository
helm repo add elastic https://helm.elastic.co
# Add Bitnami repository
helm repo add bitnami https://charts.bitnami.com/bitnami
# Add NGINX repository
helm repo add nginx https://kubernetes.github.io/ingress-nginx
# Install NGINX ingress
helm install ingress-nginx ingress-nginx --repo https://kubernetes.github.io/ingress-nginx --namespace ingress-nginx --create-namespace --set prometheus.create=true --set prometheus.port=9113 --set tcp.5044="default/nemesis-ls-beats:5044" --set controller.config."proxy-body-size"="5000m"
# Install ElasticSearch operator to manage "default" namespace. The managedNamespaces field will need to be configured if you desire to install Nemesis in a different namespace
helm install elastic-operator elastic/eck-operator --namespace elastic-system --create-namespace --set managedNamespaces='{default}'

curl https://raw.githubusercontent.com/SpecterOps/Nemesis/helm/helm/nemesis/values.yaml -o nemesis-values.yaml
curl https://raw.githubusercontent.com/SpecterOps/Nemesis/helm/helm/quickstart/values.yaml -o quickstart-values.yaml
EOF


# kick off the script with new group privileges using "newgrp"
newgrp docker <<EOF
bash /tmp/setup_part_2.sh
EOF


echo -e "\n\nNOTE: you need to run 'newgrp docker' in any new shell to interact with Docker, or logout/log back in.\n"
echo -e "Edit quickstart-values.yaml and then run:\n    echo 'helm install --repo https://specterops.github.io/Nemesis/ nemesis-quickstart quickstart -f quickstart-values.yaml' | newgrp\n"
echo -e "Then edit nemesis-values.yaml and then run:\n    echo 'helm install --repo https://specterops.github.io/Nemesis/ nemesis nemesis --timeout '45m' -f nemesis-values.yaml' | newgrp\n"
