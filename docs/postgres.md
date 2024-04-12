# Overview

In addition to Elasticsearch for an unstructed/NoSQL approach, we are using PostgreSQL to store structured data such as DPAPI blobs/masterkeys/etc.

The database schema for Postgres is at `./helm/nemesis/files/postgres/nemesis.sql`. It mimics the Protobufs defined in ./packages/nemesis.proto, **but are not guaranteed to match!**

We do not recommend interacting with Postgres directly- instead, use the [`/hasura/`](hasura.md) endpoint

# Storage

By default this PostgreSQL instance uses a persistent data store. The size of the datastore can be adjusted in [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml) by modifying the `storage: 15Gi` in the postgres section.

To use temporary storage that is wiped on every run, set the `operation.environment` value in [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml) to "test".

## pgAdmin

A pgAdmin interface is exposed at `NEMESIS_URL/pgadmin` with the credentials from [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml)
