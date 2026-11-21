# Jupyter Service

Jupyter Lab environment for exploring Nemesis data through Hasura GraphQL.

## Features

- JupyterLab with Python data science packages
- Pre-configured Hasura GraphQL client
- Sample notebooks demonstrating data exploration
- Direct access to Nemesis PostgreSQL database

## Access

Available at: `/jupyter/` when Nemesis is running

## Environment Variables

- `HASURA_GRAPHQL_URL`: Hasura GraphQL endpoint URL. Notebooks connect without the admin secret and get
  Hasura's limited `operator` role (the same role the web UI uses), which can query data and record triage
  but cannot run SQL or change metadata.