# Basics

| Description                | command                                                                                                |
|----------------------------|--------------------------------------------------------------------------------------------------------|
| View pods                  | kubectl get pods                                                                                       |
| View all pods              | kubectl get pods -A                                                                                    |
| View pod logs              | kubectl logs <podName>                                                                                 |
| Describe pod config/events | kubectl describe pods/<podName>                                                                        |
| View services              | kubectl get services [-A]                                                                              |
| Execute a command in pod   | kubectl exec -ti <podName> -- bash                                                                     |
| Run a pod temporarily      | kubectl run temptest -ti --image=jupyter/datascience-notebook:latest --rm=true --restart=Never -- bash |

May consider aliasing `kubectl` to `k` just so you don't have to type it out each time.

# Pods keep restarting due to OOMError
`OOOError` = Out of memory error

Reasons why it might happen include:
* Pod doesn't have enough memory. Solution: Look at the pod's k8s code and check the `resources` section and increase the memory in [the limits/request section](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
* The kubernetes node doesn't have enough memory to deploy the pods. Solution: If you're using Minikube, make sure the VM has enough memory and that minikube is configured to start with more memory (see the preq instructions for Minikube for how to configure the memory).
* The application has a memory leak, and over time, consumes all the available memory dedicated to it. Solution: Fix the memory leak.

# CrashLoopBackOff Error

To get information about the pod: `kubectl describe pod [name] --namespace=[namespace]`

To get the last 10 lines from the pod as it fails: `kubectl logs --previous --tail 10 pod/[name] --namespace=[namespace]`
