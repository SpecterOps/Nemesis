# PostgreSQL

In addition to Elasticsearch for an unstructed/NoSQL approach, we are using PostgreSQL to store structured data such as DPAPI blobs/masterkeys/etc.

The database schema for Postgres is at `./helm/nemesis/files/postgres/nemesis.sql`. It mimics the Protobufs defined in ./packages/nemesis.proto, **but are not guaranteed to match!**

We do not recommend interacting with Postgres directly- instead, use the [`/hasura/`](hasura.md) endpoint

## Storage

By default this PostgreSQL instance uses a persistent data store. The size of the datastore can be adjusted in [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml) by modifying the `storage: 15Gi` in the postgres section.

To use temporary storage that is wiped on every run, set the `operation.environment` value in [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml) to "test".

## pgAdmin

A pgAdmin interface is exposed at `NEMESIS_URL/pgadmin` with the credentials from [values.yaml](https://github.com/SpecterOps/Nemesis/blob/main/helm/nemesis/values.yaml)

# Port Forwarding
Command to temporarily forward the postgres service's port outside of the cluster:
```
kubectl port-forward service/postgres 5432:5432 --address=0.0.0.0
```

# Schema
As of right now, the schema is manually maintained in [nemesiscommon](../packages/python/nemesiscommon/). The tables are defined using sqlalchemy in [models.py](../packages/python/nemesiscommon/nemesiscommon/db/models.py). The SQL is generated [using alembic](../packages/python/nemesiscommon/alembic/README), combined with [stored_procs.sql](../packages/python/nemesiscommon/nemesiscommon/db/stored_procs.sql), and then stored in [nemesis.sql](../helm/nemesis/files/postgres/nemesis.sql).

In the future, we plan to support alembic migrations, but until then, this is a manual process.