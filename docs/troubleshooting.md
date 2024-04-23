# Troubleshooting, Common Errors, and Support
## Freshly Install Nemesis
If you want to start fresh again you can run the following general steps:
```
minikube delete   # delete your current cluster
minikube start    # start up minikube again

# Optionally configure Helm values in `./helm/nemesis/values.yaml`
helm install nemesis ./helm/nemesis
```

## "INSTALLATION FAILED" - "timed out waiting for the condition"
**Observed error:** You see an `INSTALLATION FAILED` error stating `timed out waiting for the condition`

**Cause:** This is usually caused due to large docker images taking a long time to pull, eventually causing Helm hit its deployment timeout.

**Fix:** Delete any resource that have been deployed:
```bash
helm uninstall nemesis    # Delete Nemesis resources
helm uninstall monitoring # Delete Monitoring resources if any were installed
kubectl delete all --all -n default
```

Then, reinstall everything but specify a higher timeout period (e.g., 90 minutes).
```bash
helm install --repo https://specterops.github.io/Nemesis/ nemesis nemesis --timeout '90m'`
```

While Nemesis is deploying, you can quickly monitor deployed pods by running the [watch_pods.sh](../scripts/watch_pods.sh) script. If the image is still pulling, usually the pod's status will be `ContainerCreating` or `Init: #/#`.  You can run `kubectl describe pods <POD_NAME>` to view some details about the pod, and if it's still pulling the image there will be an event similar to this:
```
Events:
  Type    Reason     Age    From               Message
  ----    ------     ----   ----               -------
  Normal  Scheduled  3m49s  default-scheduler  Successfully assigned default/gotenberg-855956f8b8-tls27 to minikube
  Normal  Pulling    3m47s  kubelet            Pulling image "gotenberg/gotenberg:8.0.1"
```

## "CONTAINER can't be pulled" error
When running skaffold, you may encounter an error stating:
> deployment/______ failed. Error: container _____ is waiting to start: _______ can't be pulled

This error usually occurs when on a slower internet connection and occurs because skaffold has to pull down a large docker image and eventually times out due to the download taking too long. This most commonly occurs with the gotenberg image, manifesting with this error:
> deployment/gotenberg failed. Error: container gotenberg is waiting to start: gotenberg/gotenberg:7.7.0 can't be pulled.

Two solutions:
* Run `minikube ssh docker pull CONTAINER` to manually pull an individual docker image into minikube.
* In the root of the repo run `./scripts/pull_images.sh`. This will pull all Nemesis docker images into minikube w/o using skaffold.

## Troubleshooting Minikube's Internet/DNS
The easiest way to troubleshoot internet/DNS issues is to use `minikube ssh` to get a terminal in the minikube host. From there, you can test connectivity in a variety of ways:
```
# Test internet connectivity
ping -c 1 1.1.1.1

# Test DNS
nslookup google.com

# Test docker image pulling is working
docker pull debian:11
```

If minikube can connect to the internet but DNS isn't working, add the following to `/etc/docker/daemon.json` and restart Docker with `sudo service docker restart`:
```
{
    "dns": ["8.8.8.8"]
}
```



## Need additional help?
Please [file an issue](https://github.com/SpecterOps/Nemesis/issues) or feel free to ask questions in the [#nemesis-chat channel](https://bloodhoundhq.slack.com/archives/C05KN15CCGP) in the Bloodhound Slack ([click here to join](https://ghst.ly/BHSlack)).