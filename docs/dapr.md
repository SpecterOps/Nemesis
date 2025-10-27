# Dapr

Nemesis 2.0 makes heavy use of [Dapr](https://dapr.io/), the Distributed Application Runtime. The Dapr components that Nemesis utilizes are detailed in the following sections. Images in this page were pulled from the appropriate locations from the [Dapr Documentation](https://docs.dapr.io/).

## Pubsub

Nemesis utilizes the [Dapr Publish & subscribe](https://docs.dapr.io/developing-applications/building-blocks/pubsub/) building block for its internal queueing system. Currently, Nemesis utilizes RabbitMQ for the queue, but this can easily be easily swapped for [alternative systems](https://docs.dapr.io/reference/components-reference/supported-pubsub/) like Kafka or Redis Streams by ensuring the provider is stood up in the [docker-compose.yml](https://github.com/SpecterOps/Nemesis/tree/main/docker-compose.yml), modifying the [pubsub.yaml](https://github.com/SpecterOps/Nemesis/tree/main/infra/dapr/components/pubsub.yaml) file with an alternative provider, and ensuring the connection string is passed through via an environment variable as in the current pubsub.yaml example.

![Dapr Pubsub](images/dapr-pubsub-overview-components.png)

## Workflows

[Dapr Workflows](https://docs.dapr.io/developing-applications/building-blocks/workflow/workflow-overview/) enable developers to build reliable, long-running business processes as code. They provide a way to orchestrate microservices with built-in state management, error handling, and retry logic for complex distributed applications.

![Dapr Workflow Overview](images/dapr-workflow-overview.png)

Nemesis uses in two specific places/services. First, in the [file_enrichment](https://github.com/SpecterOps/Nemesis/tree/main/projects/file_enrichment/file_enrichment/workflow.py) project, Dapr workflows are used to control the main file enrichment processing logic. The **enrichment_workflow()** function controls the main enrichment workflow, with the **enrichment_module_workflow()** function invoked as a child workflow.

The [document_conversion](https://github.com/SpecterOps/Nemesis/tree/main/projects/document_conversion/document_conversion/main.py) project also implements a Dapr workflow in the **document_conversion_workflow()** function to handle converting documents and extracting text. This is broken out into a separate project as it's a time-consuming task.

## Secrets

Nemesis uses the [Dapr Secrets management](https://docs.dapr.io/developing-applications/building-blocks/secrets/secrets-overview/) building block to protect secrets internally (like PostgreSQL connection parameters). Currently the [Local environment variables](https://docs.dapr.io/reference/components-reference/supported-secret-stores/envvar-secret-store/) component is used. These secrets are also referenced within some Dapr files such as [pubsub.yaml](https://github.com/SpecterOps/Nemesis/tree/main/infra/dapr/components/pubsub.yaml).

This reason for using this abstraction is so alternative secret management systems like [Vault or Kubernetes secrets](https://docs.dapr.io/reference/components-reference/supported-secret-stores/) can be used in the future:

![Dapr Secrets](images/dapr-secrets-overview-cloud-stores.png)

An example of retrieving secrets is in [libs/common/common/db.py](https://github.com/SpecterOps/Nemesis/blob/main/libs/common/common/db.py) which retrieves individual PostgreSQL connection parameters (`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_PARAMETERS`) and constructs the connection string.

## Service Invocation

In a few places in Nemesis, Dapr's [Service Invocation](https://docs.dapr.io/developing-applications/building-blocks/service-invocation/service-invocation-overview/) building block is used to ease the complexity of some API invocations. This building block is specifically used when calling the Gotenberg API and when calling some of the internal file enrichment APIs by the web API.
