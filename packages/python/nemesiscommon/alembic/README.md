# Generating the SQL Schema
Standup a fresh DB with docker:
# Docker
```
docker run -p 5432:5432 --rm --name postgres -e POSTGRES_PASSWORD=Qwerty12345 -e POSTGRES_USER=nemesis postgres
```

Then, run the following to generate the SQL schema.
```bash
export DB_URI="postgresql+asyncpg://nemesis:Qwerty12345@localhost:5432/nemesis"

rm -rf alembic/versions/*;   # Remove current DB versions. Eventually we'll *actually* support migrations

alembic current # Test connection
alembic revision -m "init" --autogenerate  # Initial DB
alembic upgrade --sql head  # Dump SQL
```

Combine the SQL schema with [stored_procs.sql](../nemesiscommon/db/stored_procs.sql) and store it in [nemesis.sql](../../../../helm/nemesis/files/postgres/nemesis.sql).