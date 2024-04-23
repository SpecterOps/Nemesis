# Nemesis Helm Chart
The [`nemesis` Helm chart](../helm/nemesis/) deploys Nemesis's services. You can run the chart with its default configuration using the following command:

```bash
# set operation.nemesisHttpServer to the IP you'll be accessing the server from. By default, the value is set to https://127.0.0.1:443/ for local deployments.
helm install --repo https://specterops.github.io/Nemesis/ nemesis nemesis --timeout '45m' --set operation.nemesisHttpServer="https://192.168.6.9:443/"
```

## Customizing the Deployment

If you want customize the deployment (e.g., HTTP server URI, pod CPU/memory resources, Minio disk size), you need to download the `nemesis` chart's [values.yaml](../helm/nemesis/values.yaml) file, edit it, and then run the `nemesis` chart using the customize values. You can do so with the following commands:

1. Download the quickstart chart's `values.yaml`:
```bash
helm show values --repo https://specterops.github.io/Nemesis/ nemesis nemesis > nemesis-values.yaml
```

2. Edit `nemesis-values.yaml` as you need (e.g., using `vim`)

3. Run the quickstart chart using the customized values:
```bash
helm install --repo https://specterops.github.io/Nemesis/ nemesis nemesis --timeout '45m' -f nemesis-values.yaml
```

**Note:** If you want to change any of the `nemesis` chart's configuration after everything is deployed, make the modification(s) and then run `helm upgrade nemesis ./helm/nemesis --reset-values` to apply the changes.
