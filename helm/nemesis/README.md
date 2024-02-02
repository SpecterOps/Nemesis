```bash
helm repo add elastic https://helm.elastic.co
helm install elastic-operator elastic/eck-operator --namespace elastic-system --create-namespace --set managedNamespaces='{default}'
helm dependency build
# This step may take a while because two post-install tasks must be waited on before helm wil return
helm install nemesis-helm-release .
# Run this in a different terminal to monitor the pod status
kubectl get pod -w
```

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add nginx https://kubernetes.github.io/ingress-nginx
skaffold dev
```

kubectl delete clusterrolebinding/namespace-deleter-binding clusterrole/namespace-deleter-role cm/delete-namespace-script sa/namespace-deleter