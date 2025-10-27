#!/usr/bin/env python3

import asyncio
import os

import aiohttp
import structlog
from dapr.clients import DaprClient

# Set up logging
logger = structlog.get_logger(module=__name__)

# Configuration
LLM_EMAIL = os.getenv("LLM_EMAIL", f"bedrock-chat-service@{os.getenv('EMAIL_DOMAIN', 'local')}")
if not os.getenv("LLM_EMAIL"):
    LLM_EMAIL = "nemesis@local"

MAX_BUDGET = float(os.getenv("MAX_BUDGET", "100.0"))
BUDGET_DURATION = os.getenv("BUDGET_DURATION", "30d")
LITELLM_API_URL = os.getenv("LITELLM_API_URL", "http://litellm:4000")
LITELLM_ADMIN_KEY = os.getenv("LITELLM_ADMIN_KEY")
DAPR_STATE_STORE = os.getenv("DAPR_STATE_STORE", "statestore")
MAX_RETRIES = 2
RETRY_DELAY = 5

# Token key for Dapr state store
TOKEN_KEY = "litellm_token"


async def wait_for_litellm() -> bool:
    """Wait for LiteLLM API to be available"""
    logger.debug("Checking LiteLLM API availability...")

    async with aiohttp.ClientSession() as session:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with session.get(
                    f"{LITELLM_API_URL}/health",
                    headers={"Authorization": f"Bearer {LITELLM_ADMIN_KEY}"},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as response:
                    if response.status == 200:
                        logger.info("LiteLLM API is ready")
                        return True
            except (TimeoutError, aiohttp.ClientError):
                pass

            if attempt == MAX_RETRIES:
                # Don't use logger.error which might print stack traces
                logger.info(f"LiteLLM API not available after {MAX_RETRIES} attempts")
                return False

            # Only log every 5th attempt to reduce noise
            if attempt % 5 == 0 or attempt == 1:
                logger.debug(f"Attempt {attempt}/{MAX_RETRIES}: LiteLLM not ready, continuing...")
            await asyncio.sleep(RETRY_DELAY)

    return False


async def get_token_from_dapr() -> str | None:
    """Retrieve token from Dapr state store"""
    try:
        logger.info(f"Checking Dapr state store for existing token (key: {TOKEN_KEY})...")

        with DaprClient() as client:
            result = client.get_state(DAPR_STATE_STORE, TOKEN_KEY)

            if result.data:
                token = result.data.decode("utf-8")
                if token:
                    logger.info("Found existing token in Dapr state store")
                    return token

            logger.info("No existing token found in Dapr state store")
    except Exception as e:
        logger.error(f"Unexpected error retrieving token from Dapr: {e}")

    return None


async def save_token_to_dapr(token: str) -> bool:
    """Save token to Dapr state store"""
    try:
        logger.info(f"Saving token to Dapr state store (key: {TOKEN_KEY})...")

        with DaprClient() as client:
            client.save_state(DAPR_STATE_STORE, TOKEN_KEY, token)
            logger.info("Successfully saved token to Dapr state store")
            return True

    except Exception as e:
        logger.error(f"Unexpected error saving token to Dapr: {e}")

    return False


async def validate_token(token: str) -> bool:
    """Validate that the token works with LiteLLM"""
    try:
        logger.info("Validating token...")

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{LITELLM_API_URL}/models",
                headers={"Authorization": f"Bearer {token}"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status == 200:
                    logger.info("Token validation successful")
                    return True
                else:
                    logger.error(f"Token validation failed: {response.status}")
                    response_text = await response.text()
                    logger.error(f"Response: {response_text}")

    except (TimeoutError, aiohttp.ClientError) as e:
        logger.error(f"Token validation failed: {e}")

    return False


async def create_new_token() -> str | None:
    """Create a new user/token with budget limit"""
    logger.info("Attempting to create new chat service user with budget limit...")

    async with aiohttp.ClientSession() as session:
        # Try to create new user with budget limit first
        try:
            create_payload = {
                "user_id": LLM_EMAIL,
                "user_email": LLM_EMAIL,
                "max_budget": MAX_BUDGET,
                "budget_duration": BUDGET_DURATION,
            }
            logger.info(f"create_payload: {create_payload}")

            async with session.post(
                f"{LITELLM_API_URL}/user/new",
                json=create_payload,
                headers={"Authorization": f"Bearer {LITELLM_ADMIN_KEY}", "Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status == 200:
                    response_data = await response.json()
                    token = response_data.get("key")
                    if token:
                        logger.info(f"Successfully created new chat service user with budget limit of ${MAX_BUDGET}")
                        return token

            # If user creation failed, try to generate key for existing user
            logger.info("User creation failed (likely already exists), generating new token for existing user...")

            key_payload = {"user_id": LLM_EMAIL}
            async with session.post(
                f"{LITELLM_API_URL}/key/generate",
                json=key_payload,
                headers={"Authorization": f"Bearer {LITELLM_ADMIN_KEY}", "Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status == 200:
                    response_data = await response.json()
                    token = response_data.get("key")
                    if token:
                        logger.info("Generated new API key for existing user")
                        return token

                logger.error(f"Failed to generate API key: {response.status}")
                response_text = await response.text()
                logger.error(f"Response: {response_text}")

        except (TimeoutError, aiohttp.ClientError) as e:
            logger.error(f"Failed to create token: {e}")

    return None


async def litellm_startup() -> str:
    """
    LiteLLM startup function that provisions a budget-limited token.
    Returns the token string or raises an exception if provisioning fails.
    """
    logger.debug("Starting LiteLLM token provisioning...")

    # Validate required environment variables
    if not LITELLM_ADMIN_KEY:
        raise ValueError("LITELLM_ADMIN_KEY environment variable is required")

    # Wait for LiteLLM to be ready
    if not await wait_for_litellm():
        raise RuntimeError("LiteLLM API not available")

    # Try to get existing token from Dapr state store
    existing_token = await get_token_from_dapr()

    if existing_token:
        # Validate the existing token
        if await validate_token(existing_token):
            logger.info("Using existing token from Dapr state store")
            logger.info(f"User: {LLM_EMAIL}")
            logger.info(f"Budget: ${MAX_BUDGET}")
            logger.info(f"Token: {existing_token}")
            return existing_token
        else:
            logger.warning("Existing token is invalid, creating new one...")

    # Create new token
    new_token = await create_new_token()

    if not new_token:
        raise RuntimeError("Failed to provision budget-limited token")

    # Validate the new token
    if not await validate_token(new_token):
        raise RuntimeError("New token validation failed")

    # Save token to Dapr state store
    if not await save_token_to_dapr(new_token):
        logger.warning("Failed to save token to Dapr state store")
        # Continue anyway - token still works

    logger.info("Budget-limited token provisioned successfully!")
    logger.info(f"User: {LLM_EMAIL}")
    logger.info(f"Budget: ${MAX_BUDGET}")
    logger.info(f"Token: {new_token}")

    return new_token
