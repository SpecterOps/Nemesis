# Design decisions

* Didn't go with the RabbitMQ operator because it doesn't play nicely with skaffold and is a fairly simple wrapper for the statefulset
  * Doesn't delete pods/statefulsets during shutdown
* Didn't go with just the docker container because to scale up you need to deploy them one at a time (so used a statefulset).

# Scaling

Rabbitmq scales vertifcally better (so give it more CPU + RAM)
Add more replicas by editing `./helm/nemesis/templates/rabbitmq.service.yaml`.

# Performance testing

```
kubectl run perf-test -it --rm  --image=pivotalrabbitmq/perf-test -- --uri amqp://rabbit:Qwerty12345@nemesis-rabbitmq-svc
```

# Plumber example usage:

plumber read rabbit --address="amqp://nemesis:Qwerty12345@192.168.230.42:5672" --queue-name="file_data" --exchange-name="nemesis" --binding-key=" "  --queue-durable -f

# References

* https://blog.rabbitmq.com/posts/2020/08/deploying-rabbitmq-to-kubernetes-whats-involved/
* https://github.com/GoogleCloudPlatform/click-to-deploy/tree/master/k8s/rabbitmq