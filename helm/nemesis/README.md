# Helm
```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add nginx https://kubernetes.github.io/ingress-nginx
helm repo add elastic https://helm.elastic.co
helm install elastic-operator elastic/eck-operator --namespace elastic-system --create-namespace --set managedNamespaces='{default}'
helm install ingress-nginx ingress-nginx --repo https://kubernetes.github.io/ingress-nginx --namespace ingress-nginx --create-namespace --set prometheus.create=true --set prometheus.port=9113 --set tcp.5044="default/nemesis-ls-beats:5044" --set controller.config."proxy-body-size"="5000m"
helm dependency build
# This step may take a while because two post-install tasks must be waited on before helm wil return
helm install nemesis . --timeout '10m'
# Run this in a different terminal to monitor the pod status
kubectl get pod -w
```

# Skaffold
```bash
helm repo add elastic https://helm.elastic.co
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx --repo https://kubernetes.github.io/ingress-nginx --namespace ingress-nginx --create-namespace --set prometheus.create=true --set prometheus.port=9113 --set tcp.5044="default/nemesis-ls-beats:5044" --set controller.config."proxy-body-size"="5000m"
helm install elastic-operator elastic/eck-operator --namespace elastic-system --create-namespace --set managedNamespaces='{default}'
skaffold dev
```


kubectl delete clusterrolebinding/namespace-deleter-binding clusterrole/namespace-deleter-role cm/delete-namespace-script sa/namespace-deleter