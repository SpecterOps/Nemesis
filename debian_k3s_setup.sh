#!/bin/bash

# Usage:
# This script automates the setup and deployment of Nemesis environment using k3s,
# installs necessary tools like curl, iptables, Helm, and deploys the Nemesis platform.
# It supports providing an IP address as an argument or interactively during execution.
#
# Requirements:
# - A Linux-based system with apt package manager (Debian, Ubuntu, etc.)
# - sudo privileges for the executing user
#
# How to run:
# 1. Without an IP address (interactive mode): ./debian_k3s_setup.sh
#    The script will prompt for an IP address or use the default 127.0.0.1.
# 2. With an IP address: ./debian_k3s_setup.sh <IP_Address>
#    The script will use the provided IP address for the Nemesis platform.
#
# Steps performed by the script:
# 1. Checks and installs curl and iptables if they are not already installed.
# 2. Validates the provided IP address or prompts the user for one.
# 3. Installs k3s and configures the Kubernetes environment.
# 4. Installs Helm and uses it to install necessary dependencies and the Nemesis platform.
# 5. Sets up basic authentication for Nemesis and provides login information.

sudo pwd &> /dev/null

if ! command -v curl &> /dev/null; then
    echo -e "[*] curl could not be found, attempting to install...\n"
    sudo apt-get update
    sudo apt-get install curl -y
fi

if ! command -v iptables &> /dev/null; then
    echo -e "[*] iptables could not be found, attempting to install...\n"
    sudo apt-get update
    sudo apt-get install iptables -y
fi

validate_ip() {
    if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        IFS='.' read -r -a octets <<< "$1"
        for octet in "${octets[@]}"; do
            if (( octet > 255 )); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

if [ -z "$1" ]; then
    while true; do
        read -p "No IP address provided. Would you like to use the default IP 127.0.0.1 (n) or enter another (y)? (y/n): " answer
        answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]')

        if [[ "$answer" == "y" ]]; then
            read -p "Enter an IP address or press enter to use 127.0.0.1: " user_ip
            if [ -z "$user_ip" ]; then
                IP="127.0.0.1"
            elif validate_ip "$user_ip"; then
                IP="$user_ip"
            else
                echo "Invalid IP address format. Please enter a valid IPv4 address."
                continue
            fi
            break
        elif [[ "$answer" == "n" ]]; then
            echo "No IP set, exiting script."
            exit 1
        else
            echo "Please answer 'y' or 'n'."
        fi
    done
else
    # IP was provided as argument, validate it
    if validate_ip "$1"; then
        IP="$1"
    else
        echo "Invalid IP address provided."
        exit 1
    fi
fi

echo "[*] Using IP: $IP"

# Step 1: Install k3s
echo -e "\n[*] Installing k3s...\n"
curl -sfL https://get.k3s.io | sh -
sleep 30
mkdir -p ~/.kube 

if [ -d ~/.kube ]; then
    sudo k3s kubectl config view --raw > ~/.kube/config
else
    echo "Command failed, exiting the script."
    exit 1
fi

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

# Step 4: Install the quickstart Chart
sleep 30
echo -e "\n[*] Installing Quickstart chart...\n"
helm install --repo https://specterops.github.io/Nemesis/ nemesis-quickstart quickstart

# Step 5: Install Nemesis chart
sleep 30
echo -e "\n[*] Installing Nemesis chart...\n"
helm install --repo https://specterops.github.io/Nemesis/ nemesis nemesis --timeout '45m' --set operation.nemesisHttpServer="https://$IP:443/"

export NEMESIS_BASIC_AUTH_USER=$(sudo kubectl get secret --namespace "default" basic-auth -o jsonpath="{.data.username}" | base64 -d)
export NEMESIS_BASIC_AUTH_PASSWORD=$(sudo kubectl get secret --namespace "default" basic-auth -o jsonpath="{.data.password}" | base64 -d)

clear -x
echo -e "\n[*] Nemesis installed, but some pods may still be standing up for the next 5-10 minutes."
echo -e "[*] You can check pod deployment status with 'sudo kubectl get pods -A'"
echo -e "[*] Once all pods are up, browse to https://$IP:443/ and log in with '$NEMESIS_BASIC_AUTH_USER:$NEMESIS_BASIC_AUTH_PASSWORD'\n"
