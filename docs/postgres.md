# Overview

In addition to Elasticsearch for an unstructed/NoSQL approach, we are using PostgreSQL to store structured data such as DPAPI blobs/masterkeys/etc.

The database schema for Postgres is at `./kubernetes/postgres/configmap.yaml`. It mimics the Protobufs defined in ./packages/nemesis.proto, **but are not guaranteed to match!**

The default persistent storage size is 15Gi. To change this, modify the *two* `storage: 15Gi` entries under the **PersistentVolume** and **PersistentVolumeClaim** sections in ./kubernetes/postgres/deployment.yaml

# Storage

By default this PostgreSQL instance uses a persistent data store. The size of the datastore can be adjusted in `./kubernetes/postgres/deployment.yaml` by modifying the `storage: 15Gi` in the "PersistentVolume" and "PersistentVolumeClaim" config sections.

To use temporary storage that is wiped on every Skaffold run, check out the `Option 1)` comment in `./kubernetes/postgres/deployment.yaml`

## pgAdmin

A pgAdmin interface is exposed at `NEMESIS_URL/pgadmin` with the credentials (PGADMIN_EMAIL/PGADMIN_PASSWORD) set in the common config.

# Port Forwarding
Command to temporarily forward the postgres service's port outside of the cluster:
```
kubectl port-forward service/postgres 5432:5432 --address=0.0.0.0
```