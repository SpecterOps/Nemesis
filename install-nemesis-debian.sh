#!/bin/bash

sudo apt update
sudo apt install -y git apt-transport-https ca-certificates curl make gcc build-essential libz-dev libffi-dev libbz2-dev libncurses-dev libreadline-dev build-essential libreadline-dev libssl-dev libsqlite3-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev libssl-dev liblzma-dev

if [ ! -d /opt/Nemesis ]; then
	sudo git clone https://github.com/SpecterOps/Nemesis /opt/Nemesis
else
	sudo git -C /opt/Nemesis pull --rebase --autostash
fi
sudo chown -R "$(id -nu):$(id -ng)" /opt/Nemesis

sudo mkdir /etc/apt/keyrings/ 2>/dev/null
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list

if [ ! $(command -v docker) ]; then
	curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
	sudo sh /tmp/get-docker.sh
fi
sudo apt install -y docker-compose kubectl helm
sudo usermod -aG docker ${USER}

curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
minikube config set memory 12288
minikube config set cpus 3
minikube start

curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/v2.7.1/skaffold-linux-amd64 && chmod +x skaffold && sudo mv skaffold /usr/local/bin
skaffold config set --global collect-metrics false

cat <<-EOF >> ~/.bashrc
	export PATH="\$HOME/.local/bin:\$PATH"
	export PYENV_ROOT="\$HOME/.pyenv"
	command -v pyenv >/dev/null || export PATH="\$PYENV_ROOT/bin:\$PATH"
	
	eval "\$(pyenv init -)"
EOF

export PATH="$HOME/.local/bin:$PATH"

curl https://pyenv.run | bash

export PYENV_ROOT="$HOME/.pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

pyenv install 3.11.6
pyenv global 3.11.6
python3 -c 'from urllib.request import urlopen; print(urlopen("https://install.python-poetry.org").read().decode())' | python3 -

export PATH="/home/ansible/.local/bin:$PATH"

poetry -C /opt/Nemesis/cmd/enrichment/ install
python3 -m pip install boto3 vyper-config passlib

cd /opt/Nemesis/
python3 nemesis-cli.py --disable_slack_alerting true --assessment_id ASSESS-TEST --nemesis_http_server http://10.1.0.4:8080
skaffold run -m nemesis --port-forward=user
