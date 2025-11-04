"""Rate limit handling for HTTP clients with Retry-After support."""

import openai
from agents.litellm_startup import litellm_startup
from common.logger import get_logger
from gql import gql
from httpx import AsyncClient, HTTPStatusError
from pydantic_ai.retries import AsyncTenacityTransport, wait_retry_after
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = get_logger(__name__)


def create_rate_limit_client():
    """Create a client that respects Retry-After headers from rate limiting responses."""

    def validator(response):
        """Safely validate response."""
        try:
            # Check if response has a status_code attribute
            if hasattr(response, "status_code"):
                if response.status_code >= 400:
                    response.raise_for_status()
            else:
                print(f"WARNING: Response object doesn't have status_code: {type(response)}")
        except Exception as e:
            print(f"Validator exception: {type(e).__name__}: {e}")
            # Only re-raise HTTP errors, not other exceptions
            if isinstance(e, HTTPStatusError):
                raise

    transport = AsyncTenacityTransport(
        controller=AsyncRetrying(
            retry=retry_if_exception_type(HTTPStatusError),
            wait=wait_retry_after(
                fallback_strategy=wait_exponential(multiplier=1, max=60),
                max_wait=300,  # Don't wait more than 5 minutes
            ),
            stop=stop_after_attempt(10),
            reraise=True,
        ),
        validate_response=validator,
    )

    return AsyncClient(transport=transport)


async def get_litellm_token():
    """Sets up the LiteLLM token."""

    litellm_token = None

    try:
        try:
            litellm_token = await litellm_startup()
        except RuntimeError as e:
            # Handle LiteLLM not being available gracefully
            if "LiteLLM API not available" in str(e):
                logger.warning("LiteLLM service is not available")
            else:
                logger.warning(f"LiteLLM initialization failed: {e}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error initializing LiteLLM: {e}")
            return None

        # Check available models if we have a token
        models = []
        if litellm_token:
            try:
                client = openai.OpenAI(base_url="http://litellm:4000/", api_key=litellm_token)
                models = [model.id for model in client.models.list().data]
            except Exception as e:
                logger.error(f"Error initializing OpenAI client for https://litellm:4000: {e}")
                return None

            if models:
                return litellm_token
            else:
                logger.warning("No models available: LLM finding triage disabled", available_models=models)
                return None
        else:
            logger.warning("No LiteLLM token available - LLM-based triage disabled")
            return None

    except Exception as e:
        logger.error(e, message="Error initializing LiteLLM connection")
        return None


async def fetch_finding_details(session, finding_id):
    """Fetch full details for a finding after receiving its ID from subscription"""
    FINDING_DETAILS_QUERY = gql("""
        query FindingDetails($finding_id: bigint!) {
            findings_by_pk(finding_id: $finding_id) {
                finding_name
                category
                severity
                object_id
                origin_type
                origin_name
                data
                raw_data
                files_enriched {
                    path
                    object_id
                }
            }
        }
    """)

    try:
        result = await session.execute(FINDING_DETAILS_QUERY, variable_values={"finding_id": finding_id})

        finding_details = result.get("findings_by_pk")
        if not finding_details:
            logger.warning(f"No details found for finding ID {finding_id}")
            return None

        return finding_details
    except Exception:
        logger.exception(message=f"Error fetching details for finding ID {finding_id}")
        return None


def check_triage_consensus(session, object_id, threshold=3):
    """Check if there's a consensus for triage decisions on a file.

    Returns:
        dict: {'has_consensus': bool, 'decision': str, 'count': int} if consensus exists
        None: if no consensus
    """
    TRIAGE_CONSENSUS_QUERY = gql("""
        query TriageConsensus($object_id: uuid!) {
            findings(where: {object_id: {_eq: $object_id}}) {
                finding_id
                finding_triage_histories(where: {automated: {_eq: true}}) {
                    value
                }
            }
        }
    """)

    try:
        result = session.execute(TRIAGE_CONSENSUS_QUERY, variable_values={"object_id": object_id})

        findings = result.get("findings", [])
        if not findings:
            return None

        decision_counts = {"true_positive": 0, "false_positive": 0}

        for finding in findings:
            triage_histories = finding.get("finding_triage_histories", [])
            if triage_histories:
                # Get the most recent triage decision for this finding
                latest_value = triage_histories[0].get("value")
                if latest_value in decision_counts:
                    decision_counts[latest_value] += 1

        # Check if we have consensus
        for decision, count in decision_counts.items():
            if count >= threshold:
                logger.info(f"Found triage consensus for object {object_id}: {decision} ({count} findings)")
                return {"has_consensus": True, "decision": decision, "count": count}

        return None

    except Exception:
        logger.exception(message=f"Error checking triage consensus for object {object_id}")
        return None
