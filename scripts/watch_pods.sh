#!/bin/bash

watch -n 1 'kubectl get pods -A | grep -Ev "kube-(proxy|controller|apiserver|scheduler|state-metrics|system)|coredns-|etcd-minikube|storage-prov|vpnkit" | (sed -u 1q; sort)'
