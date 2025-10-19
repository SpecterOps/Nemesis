from functools import lru_cache

from dapr.clients import DaprClient

_POSTGRES_SECRET_NAME = "POSTGRES_CONNECTION_STRING"
_DAPR_SECRET_STORE_NAME = "nemesis-secret-store"


@lru_cache(maxsize=1)
def get_postgres_connection_str(dapr_client: DaprClient | None = None) -> str:
    """Get PostgreSQL connection string from Dapr."""

    if dapr_client:
        secret = dapr_client.get_secret(store_name=_DAPR_SECRET_STORE_NAME, key=_POSTGRES_SECRET_NAME)
        output = secret.secret[_POSTGRES_SECRET_NAME]
    else:
        with DaprClient() as client:
            secret = client.get_secret(store_name=_DAPR_SECRET_STORE_NAME, key=_POSTGRES_SECRET_NAME)
            output = secret.secret[_POSTGRES_SECRET_NAME]

    if not output.startswith("postgresql://"):
        raise ValueError("POSTGRES_CONNECTION_STRING must start with 'postgresql://' to be used with the DpapiManager")

    return output
