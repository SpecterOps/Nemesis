"""Sync LiteLLM model pricing to Phoenix for cost tracking."""

import os

import asyncpg
import httpx
import structlog
from dapr.clients import DaprClient

logger = structlog.get_logger(__name__)


async def fetch_litellm_model_info(admin_key: str) -> dict | None:
    """
    Fetch model information including pricing from LiteLLM.

    Args:
        admin_key: LiteLLM admin API key

    Returns:
        Dictionary containing model info or None if request fails
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "http://litellm:4000/model/info", headers={"Authorization": f"Bearer {admin_key}"}, timeout=10.0
            )
            response.raise_for_status()
            return response.json()
    except Exception as e:
        logger.error(f"Failed to fetch LiteLLM model info: {e}")
        return None


def extract_model_pricing(model_info: dict, model_name: str = "default") -> dict | None:
    """
    Extract pricing information for a specific model from LiteLLM response.

    Args:
        model_info: Full response from LiteLLM /model/info endpoint
        model_name: Name of the model to extract pricing for

    Returns:
        Dictionary with pricing info or None if model not found
    """
    for model in model_info.get("data", []):
        if model.get("model_name") == model_name:
            info = model.get("model_info", {})

            # Both LiteLLM and Phoenix use cost per token (not per million)
            # For example: $3/million tokens = 0.000003 per token
            input_cost_per_token = info.get("input_cost_per_token", 0)
            output_cost_per_token = info.get("output_cost_per_token", 0)

            # Special token costs if available
            cache_creation_cost = info.get("cache_creation_input_token_cost", 0)
            cache_read_cost = info.get("cache_read_input_token_cost", 0)

            return {
                "model_name": model_name,
                "provider": "litellm",
                # Cost per token (same format for both LiteLLM and Phoenix)
                "input_cost_per_token": input_cost_per_token,
                "output_cost_per_token": output_cost_per_token,
                # Additional token type costs
                "cache_creation_cost_per_token": cache_creation_cost,
                "cache_read_cost_per_token": cache_read_cost,
                # Original model backend info
                "backend_model": model.get("litellm_params", {}).get("model", "unknown"),
                "backend_provider": info.get("litellm_provider", "unknown"),
            }

    logger.warning(f"Model '{model_name}' not found in LiteLLM response")
    return None


async def insert_phoenix_model_pricing(database_url: str, model_name: str, pricing: dict) -> bool:
    """
    Insert model and pricing data directly into Phoenix PostgreSQL database.

    Args:
        database_url: PostgreSQL connection string
        model_name: Name of the model
        pricing: Dictionary containing pricing information

    Returns:
        True if successful, False otherwise
    """
    conn = None
    try:
        # Connect to Phoenix database
        conn = await asyncpg.connect(database_url)

        # Start a transaction
        async with conn.transaction():
            # First check if model already exists
            existing_model = await conn.fetchrow(
                """
                SELECT id FROM generative_models
                WHERE name = $1 AND deleted_at IS NULL
                """,
                model_name,
            )

            if existing_model:
                model_id = existing_model["id"]
                logger.info(f"Model '{model_name}' already exists with ID {model_id}, updating pricing")

                # Delete existing token prices for this model
                await conn.execute("DELETE FROM token_prices WHERE model_id = $1", model_id)
            else:
                # Insert new model into generative_models table
                model_id = await conn.fetchval(
                    """
                    INSERT INTO generative_models
                    (name, name_pattern, provider, is_built_in, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, NOW(), NOW())
                    RETURNING id
                    """,
                    model_name,  # name
                    model_name,  # name_pattern (same as name for exact match)
                    "litellm",  # provider (required field, cannot be NULL)
                    False,  # is_built_in
                )
                logger.info(f"Created new model '{model_name}' with ID {model_id}")

            # Insert token prices for input tokens
            await conn.execute(
                """
                INSERT INTO token_prices
                (model_id, token_type, is_prompt, base_rate, customization)
                VALUES ($1, $2, $3, $4, $5)
                """,
                model_id,
                "input",  # token_type
                True,  # is_prompt
                pricing["input_cost_per_token"],  # base_rate (cost per token)
                None,  # customization (no customization)
            )

            # Insert token prices for output tokens
            await conn.execute(
                """
                INSERT INTO token_prices
                (model_id, token_type, is_prompt, base_rate, customization)
                VALUES ($1, $2, $3, $4, $5)
                """,
                model_id,
                "output",  # token_type
                False,  # is_prompt
                pricing["output_cost_per_token"],  # base_rate (cost per token)
                None,  # customization (no customization)
            )

            logger.info(
                f"Inserted token prices for model {model_id}: "
                f"input=${pricing['input_cost_per_token']}/token, "
                f"output=${pricing['output_cost_per_token']}/token"
            )

        return True

    except Exception:
        logger.exception(message="Failed to insert model pricing into Phoenix database")
        return False
    finally:
        if conn:
            await conn.close()


async def sync_pricing_to_phoenix(model_name: str = "default") -> bool:
    """
    Sync model pricing from LiteLLM to Phoenix database.

    This function:
    1. Fetches the LITELLM_ADMIN_KEY from environment or Dapr secret store
    2. Gets model pricing from LiteLLM
    3. Inserts/updates the model and pricing in Phoenix PostgreSQL database

    Args:
        model_name: Name of the model to sync pricing for

    Returns:
        True if sync was successful, False otherwise
    """
    try:
        # Get Phoenix database URL from environment
        phoenix_db_url = os.getenv("PHOENIX_SQL_DATABASE_URL")
        if not phoenix_db_url:
            logger.error("PHOENIX_SQL_DATABASE_URL not set in environment")
            return False

        # Get LiteLLM admin key - try environment first, then Dapr
        admin_key = os.getenv("LITELLM_ADMIN_KEY")
        if not admin_key:
            try:
                with DaprClient() as client:
                    secret = client.get_secret(store_name="nemesis-secret-store", key="LITELLM_ADMIN_KEY")
                    admin_key = secret.secret.get("LITELLM_ADMIN_KEY")
            except Exception as e:
                logger.warning(f"Could not get LITELLM_ADMIN_KEY from Dapr: {e}")

        if not admin_key:
            logger.error("LITELLM_ADMIN_KEY not found in environment or secret store")
            return False

        # Fetch model info from LiteLLM
        model_info = await fetch_litellm_model_info(admin_key)
        if not model_info:
            return False

        # Extract pricing for our model
        pricing = extract_model_pricing(model_info, model_name)
        if not pricing:
            return False

        logger.info(
            "Extracted model pricing from LiteLLM",
            model_name=model_name,
            input_cost_per_token=pricing["input_cost_per_token"],
            output_cost_per_token=pricing["output_cost_per_token"],
            backend_model=pricing["backend_model"],
        )

        # Insert pricing into Phoenix database
        success = await insert_phoenix_model_pricing(phoenix_db_url, model_name, pricing)

        if success:
            # Also store in environment for reference
            os.environ["PHOENIX_MODEL_NAME"] = model_name
            os.environ["PHOENIX_MODEL_PROVIDER"] = "litellm"
            os.environ["PHOENIX_INPUT_COST_PER_TOKEN"] = str(pricing["input_cost_per_token"])
            os.environ["PHOENIX_OUTPUT_COST_PER_TOKEN"] = str(pricing["output_cost_per_token"])

            logger.info(
                "Model pricing successfully synced to Phoenix database",
                model_name=model_name,
                input_cost_per_token=pricing["input_cost_per_token"],
                output_cost_per_token=pricing["output_cost_per_token"],
            )

        return success

    except Exception:
        logger.exception(message="Failed to sync pricing to Phoenix")
        return False


def get_synced_pricing() -> dict | None:
    """
    Get the synced pricing information from environment variables.

    Returns:
        Dictionary with pricing info or None if not set
    """
    model_name = os.getenv("PHOENIX_MODEL_NAME")
    if not model_name:
        return None

    return {
        "model_name": model_name,
        "provider": os.getenv("PHOENIX_MODEL_PROVIDER", "litellm"),
        "input_cost_per_token": float(os.getenv("PHOENIX_INPUT_COST_PER_TOKEN", "0")),
        "output_cost_per_token": float(os.getenv("PHOENIX_OUTPUT_COST_PER_TOKEN", "0")),
    }
