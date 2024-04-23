# Quickstart Helm Chart
The purpose of the [`quickstart` Helm chart](../helm/quickstart/) is to configure and set secrets for each Nemesis service (e.g., usernames and passwords and ingress TLS certificates). You can run the quickstart chart with the following command:

```bash
helm install --repo https://specterops.github.io/Nemesis/ nemesis-quickstart quickstart
```

The output will contain Bash commands you can run to store the configured secrets in environment variables (by default, all secrets are randomized). For example, after you run the output Bash commands in a terminal, you can view the username/password to login to Nemesis's dashboard by running the following:

```bash
echo "Basic Auth Username: ${BASIC_AUTH_USER}"
echo "Basic Auth Password: ${BASIC_AUTH_PASSWORD}"
```

# Customizing the Configuration
If you want customize any of the services' secrets, you need to download the `quickstart` chart's [values.yaml](../helm/quickstart/values.yaml) file, edit it, and then run the `quickstart` chart using the customized values. You can do so with the following commands:

1. Download the quickstart chart's `values.yaml`:
```bash
curl https://raw.githubusercontent.com/SpecterOps/Nemesis/helm/helm/quickstart/values.yaml -o quickstart-values.yaml
```

2. Edit `quickstart-values.yaml` as needed (e.g., using `vim`)

3. Run the quickstart chart using the customized values:
```bash
helm install --repo https://specterops.github.io/Nemesis/ nemesis-quickstart quickstart -f quickstart-values.yaml
```
