# Dev Software Requirements

**The following requirements need to be installed for development:**

<details>
<summary>
Install the Protobuf Compiler
</summary>

**Purpose:** Compiles protobuf specs to python (or other languages).

* Install protobuf-compiler package
```bash
# Install the protobuf compiler
wget https://github.com/protocolbuffers/protobuf/releases/download/v21.5/protoc-21.5-linux-x86_64.zip
sudo apt-get install -y zip
sudo unzip protoc-21.5-linux-x86_64.zip -d /usr/local/
```
</details>


# Running Nemesis during Dev

1. Run `nemesis-cli.py`.  This script ensures minikube is started with sufficient resources, tests access to AWS resources (and optionally creates them), and adds secrets to the k8s cluster (and generates random ones if wanted).

2. Start Nemesis. The output of `nemesis-cli.py` will contain some instructions on how to start Nemesis. In general during dev, Nemesis's infrastructure and services are started separately:

```
# Start fairly static services (Elastic, RabbitMQ, kibana, jupyter, tika, gotenberg, etc)
./scripts/infra_start.sh

# Start up the data ingest/enrichment services. If you pass any args to this command, the "enrichment" service will NOT start
./scripts/services_start.sh
```

These scripts are just wrappers around skaffold commands.

**Note 1 - Image pull timeouts**

Sometimes right after a minikube cluster is created, it takes a while for all the docker images to be downloaded into minikube. Skaffold may timeout during this time and tear down all the infrastructure. If this happens, you can usually just run skaffold again without issue.


# Service Development

The recommended way to develop a new (or modify a current) service is with VS Code
and a remote workspace. This allows you to write and debug code without having to
deploy the complete container.

To do this, [follow this guide](https://code.visualstudio.com/docs/remote/ssh) to
set up remote SSH for development - we recommend having the code itself reside
on a supported Debian 11 image and remoting in from your main OS for development.
Once the remote session has been established:

- Open up **just** the module folder in ./cmd/ (e.g., `enrichment`)
- Go to `Terminal` -> `New Terminal`
- (First time) activate the Poetry environment with `poetry install`
- Ensure a `./vscode/launch.json` is present (see ./cmd/enrichment for an example)
- Create a `.env` file in the root directory that contains VAR=val environment variables to set
- Start the needed Nemesis infrastructure on the host, minus this module.
  - Ensure the needed ports (RabbitMQ/etc.) are exposed locally
- On the left click the `Run and Debug` button and launch the application

**Note:** If you want to reset your Poetry environment, [see this post](https://stackoverflow.com/a/70064450).


# Building and Troubleshooting Docker Images
You can build and troubleshoot Nemesis's docker containers using the docker CLI. For example, to troublehshoot the enrichment image you can do the following:

1. Build the image and give it a name of "test"
```bash
docker build -t test -f ./dockerfiles/enrichment.Dockerfile
```

2. Run the "test" image and do your troubleshooting via a bash prompt:
```bash
docker run --rm -ti test bash
```

To build the images inside of k8s, you can use skaffold:
```bash
skaffold build
```

# Testing file processing
One can test file processing using the `./scripts/submit_to_nemesis.sh` script. To configure the script, modify the settings in `./cmd/enrichment/enrichment/cli/submit_to_nemesis/submit_to_nemesis.yaml`.

The `./sample_files/` folder contains many examples of files that Nemesis can process. For example, to test Nemesis's ability to extract a .ZIP file and process all the files inside of the zip, configure the YAML file and then run (make sure to specify the absolute path):
```bash

./scripts/submit_to_nemesis.sh -f ./sample_files/zip_test.zip
```

To see a list of all command line arguments run `./scripts/submit_to_nemesis.sh -h`.

# kubectl / kubernetes version skews

According to [kubernetes](https://kubernetes.io/releases/version-skew-policy/#kubectl) it's the best practice to keep kubectl and the kubernetes image used by minikube in sync. You can tell the versions of both with:

```bash
kubectl version --short
Flag --short has been deprecated, and will be removed in the future. The --short output will become the default.
Client Version: v1.27.1
Kustomize Version: v5.0.1
Server Version: v1.24.3
WARNING: version difference between client (1.27) and server (1.24) exceeds the supported minor version skew of +/-1
```

You can update kubectl with:
```bash
sudo apt-get update
sudo apt-get install -y kubectl
```

If you want to specify a version for kubectl, use:
```bash
curl -LO https://dl.k8s.io/release/v1.25.4/bin/linux/amd64/kubectl
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

You can then specify the kubernetes imge pulled by minikube with:
```bash
minikube start --kubernetes-version v1.25.4
```

# ./scripts/

The following describes the files in the ./scripts/ directory:

| File                  | Purpose                                                                     |
| --------------------- | --------------------------------------------------------------------------- |
| build_protobufs.sh    | Builds the protobuf definition file.                                        |
| dashboard_start.sh    | Starts the dashboard container.                                             |
| infra_start.sh        | Starts the stable backend infrastructure pods.                              |
| interact.sh           | Takes a pod name an interacts with the main system's bash env.              |
| pod_resource_usage.sh | Displays an a continuously updated state of the pods' resource utilization. |
| pull_images.sh        | Downloads all docker iamges used by Nemesis.                                |
| services_start.sh     | Starts the main processing service pods.                                    |
| submit_to_nemesis.sh  | Helper to manually submit a file to Nemesis.                                |
| total_memory.sh       | Displays the total memory currently being used by the cluster.              |
| watch_pods.sh         | Displays an a continuously updated state of the pods' status(es).           |
