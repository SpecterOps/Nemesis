# Overview

In addition to Elasticsearch for an unstructed/NoSQL approach, we are using PostgreSQL to store structured data such as DPAPI blobs/masterkeys/etc.

The database schema for Postgres is at `./kubernetes/postgres/configmap.yaml`. It mimics the Protobufs defined in ./packages/nemesis.proto, **but are not guaranteed to match!**

The default persistent storage size is 15Gi. To change this, modify the *two* `storage: 15Gi` entries under the **PersistentVolume** and **PersistentVolumeClaim** sections in ./kubernetes/postgres/deployment.yaml

We do not recommend interacting with Postgres directly- instead, use the [`/hasura/`](#hasura.md) endpoint

# Storage

By default this PostgreSQL instance uses a persistent data store. The size of the datastore can be adjusted in `./kubernetes/postgres/deployment.yaml` by modifying the `storage: 15Gi` in the "PersistentVolume" and "PersistentVolumeClaim" config sections.

To use temporary storage that is wiped on every Skaffold run, check out the `Option 1)` comment in `./kubernetes/postgres/deployment.yaml`. This is automatically done for the `dev` mode profile in skaffold.

## pgAdmin

A pgAdmin interface is exposed at `NEMESIS_URL/pgadmin` with the credentials (PGADMIN_EMAIL/PGADMIN_PASSWORD) set in the common config.
