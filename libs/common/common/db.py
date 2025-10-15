from functools import lru_cache

from dapr.clients import DaprClient


@lru_cache(maxsize=1)
def get_postgres_connection_str(dapr_client: DaprClient | None = None) -> str:
    """Get PostgreSQL connection string from Dapr."""

    if dapr_client:
        secret = dapr_client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
        return secret.secret["POSTGRES_CONNECTION_STRING"]
    else:
        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
            return secret.secret["POSTGRES_CONNECTION_STRING"]
