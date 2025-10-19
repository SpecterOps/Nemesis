from functools import lru_cache
from urllib.parse import quote_plus

from dapr.clients import DaprClient

_DAPR_SECRET_STORE_NAME = "nemesis-secret-store"


@lru_cache(maxsize=1)
def get_postgres_connection_str(dapr_client: DaprClient | None = None) -> str:
    """Get PostgreSQL connection string from Dapr secrets by building it from individual parameters."""

    def fetch_secrets(client: DaprClient) -> dict:
        """Fetch all required PostgreSQL secrets."""
        secrets = {}
        secret_keys = ["POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_PARAMETERS"]

        for key in secret_keys:
            try:
                secret = client.get_secret(store_name=_DAPR_SECRET_STORE_NAME, key=key)
                secrets[key] = secret.secret[key]
            except Exception as e:
                raise ValueError(f"Failed to fetch {key} from Dapr secret store: {e}") from e

        return secrets

    if dapr_client:
        secrets = fetch_secrets(dapr_client)
    else:
        with DaprClient() as client:
            secrets = fetch_secrets(client)

    # Build the connection string from individual parameters
    # URL-encode user and password to handle special characters like @, :, /, etc.
    user = quote_plus(secrets["POSTGRES_USER"])
    password = quote_plus(secrets["POSTGRES_PASSWORD"])
    host = secrets["POSTGRES_HOST"]
    port = secrets["POSTGRES_PORT"]
    db = secrets["POSTGRES_DB"]
    parameters = secrets["POSTGRES_PARAMETERS"]

    output = f"postgresql://{user}:{password}@{host}:{port}/{db}?{parameters}"

    if not output.startswith("postgresql://"):
        raise ValueError("Constructed POSTGRES connection string must start with 'postgresql://'")

    return output
