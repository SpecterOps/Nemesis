#!/bin/bash

#watch -n 1 '

watch -n 1 "kubectl top pods -A | grep -v 'kube-system' | grep -v 'NAMESPACE' | awk '{print \$4}' | sed s/Mi// | paste -sd+ | bc"
