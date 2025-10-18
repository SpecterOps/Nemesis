# projects/agents/agents/main.py
import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime

import asyncpg
import structlog
from agents.agent_manager import agent_manager
from agents.helpers import check_triage_consensus, fetch_finding_details, get_litellm_token
from agents.model_manager import ModelManager
from agents.phoenix_cost_sync import sync_pricing_to_phoenix
from agents.prompt_manager import PromptManager
from agents.schemas import NoseyParkerData, TriageCategory, TriageRequest, TriageResult
from agents.tasks.credential_analyzer import analyze_credentials
from agents.tasks.dotnet_analyzer import analyze_dotnet_assembly
from agents.tasks.summarizer import summarize_text
from agents.tasks.translate import translate_text
from dapr.clients import DaprClient

# from dapr.ext.fastapi import DaprApp # needed if we're doing pub/sub
from dapr.ext.workflow import DaprWorkflowClient, DaprWorkflowContext, WorkflowRuntime
from dapr.ext.workflow.logger.options import LoggerOptions
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext
from fastapi import FastAPI
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport
from gql.transport.websockets import WebsocketsTransport

from .logger import WORKFLOW_CLIENT_LOG_LEVEL, WORKFLOW_RUNTIME_LOG_LEVEL, configure_logging

configure_logging()
logger = structlog.get_logger(module=__name__)

db_pool = None
workflow_client: DaprWorkflowClient = None

litellm_model = "default"

workflow_runtime = WorkflowRuntime(logger_options=LoggerOptions(log_level=WORKFLOW_RUNTIME_LOG_LEVEL))

with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="HASURA_ADMIN_SECRET")
    hasura_admin_secret = secret.secret["HASURA_ADMIN_SECRET"]
    logger.info("[agents] HASURA_ADMIN_SECRET retrieved")


# Configuration
dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
gotenberg_url = f"http://localhost:{dapr_port}/v1.0/invoke/gotenberg/method/forms/libreoffice/convert"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events"""
    global workflow_runtime, workflow_client, litellm_model
    try:
        # setup the LiteLLM connection/token (if available)
        litellm_token = await get_litellm_token()
        logger.debug(f"LiteLLM token: {litellm_token}")

        # Initialize OpenTelemetry tracer provider first (needed for Phoenix)
        from agents.logger import get_tracer

        tracer = get_tracer("agents")
        logger.debug("OpenTelemetry tracer initialized")

        # Initialize ModelManager if we have a model
        #   this is so we can pull the custom pricing and sync it back to Phoenix for tracking
        if litellm_token:
            ModelManager.initialize(litellm_token, litellm_model)
            logger.info("ModelManager initialized", litellm_model=litellm_model, litellm_token=litellm_token)

            # Sync model pricing to Phoenix if we can reach LiteLLM and have Phoenix DB configured
            phoenix_db_url = os.getenv("PHOENIX_SQL_DATABASE_URL")
            if phoenix_db_url:
                try:
                    pricing_synced = await sync_pricing_to_phoenix(litellm_model)
                    if pricing_synced:
                        logger.info(f"Successfully synced pricing for model '{litellm_model}' to Phoenix")
                    else:
                        logger.debug(
                            f"Could not sync pricing for model '{litellm_model}' to Phoenix (LiteLLM may be unavailable)"
                        )
                except Exception as e:
                    logger.debug(f"Could not sync pricing to Phoenix: {e}")

        # Initialize PromptManager
        PromptManager.initialize()
        logger.info("PromptManager initialized")

        # Load and register agents
        agent_manager.load_agents()
        agent_manager.register_activities(workflow_runtime)
        logger.info("Agent manager initialized and activities registered")

        # start the workflow runtime
        workflow_runtime.start()
        logger.debug("Started Dapr runtime")

        # Initialize workflow client
        workflow_client = DaprWorkflowClient(
            logger_options=LoggerOptions(log_level=WORKFLOW_CLIENT_LOG_LEVEL),
        )
        logger.debug("Started Dapr workflow client")

        # Now that everything is initialized, save agent prompts to database
        agent_manager.initialize_agent_prompts()
        logger.info("Agent prompts initialized in database")

        # Start findings subscription
        asyncio.create_task(handle_findings_subscription())
        logger.debug("Started findings subscription handler")

    except Exception as e:
        logger.exception(e, message="Error initializing service")
        raise

    yield

    # Cleanup on shutdown
    try:
        logger.info("Starting service shutdown cleanup")

        # PromptManager cleanup no longer needed with sync operations

        # Shutdown workflow runtime
        if workflow_runtime:
            workflow_runtime.shutdown()
            logger.info("Workflow runtime shutdown completed")

    except Exception as e:
        logger.warning("Error during service shutdown", error=str(e))


app = FastAPI(lifespan=lifespan)

# Instrument FastAPI with OpenTelemetry if monitoring is enabled
# dapr_app = DaprApp(app) # for pub/sub, if used


# Workflow Activities


@workflow_runtime.activity
def check_consensus_activity(ctx: WorkflowActivityContext, activity_input: dict):
    """Check if there's a triage consensus for the file associated with this finding."""
    try:
        object_id = activity_input["object_id"]
        threshold = activity_input.get("threshold", 3)

        transport = RequestsHTTPTransport(
            url="http://hasura:8080/v1/graphql",
            headers={"x-hasura-admin-secret": hasura_admin_secret},
        )

        with Client(
            transport=transport,
            fetch_schema_from_transport=True,
        ) as session:
            consensus = check_triage_consensus(session, object_id, threshold)
            return consensus

    except Exception as e:
        logger.exception(e, message=f"Error checking consensus for object {object_id}")
        return None


@workflow_runtime.activity
def insert_triage_result(ctx: WorkflowActivityContext, activity_input: dict):
    """Insert triage result into Hasura via GraphQL mutation."""
    try:
        triage_result = activity_input["triage_result"]
        finding_id = activity_input["finding_id"]

        INSERT_TRIAGE = gql("""
            mutation InsertTriage($finding_id: bigint!, $username: String!, $value: String!, $explanation: String!, $confidence: Float!, $true_positive_context: String, $automated: Boolean!) {
                insert_findings_triage_history_one(object: {
                    finding_id: $finding_id,
                    username: $username,
                    value: $value,
                    explanation: $explanation,
                    confidence: $confidence,
                    true_positive_context: $true_positive_context,
                    automated: $automated
                }) {
                    id
                }
            }
        """)

        transport = RequestsHTTPTransport(
            url="http://hasura:8080/v1/graphql",
            headers={"x-hasura-admin-secret": hasura_admin_secret},
        )

        with Client(
            transport=transport,
            fetch_schema_from_transport=True,
        ) as session:
            variable_values = {
                "finding_id": finding_id,
                "username": "automatation_agent",
                "value": triage_result["decision"],
                "explanation": triage_result["explanation"],
                "confidence": triage_result["confidence"],
                "automated": True,
            }

            # Add true_positive_context if it exists
            if "true_positive_context" in triage_result:
                variable_values["true_positive_context"] = triage_result["true_positive_context"]
            else:
                variable_values["true_positive_context"] = None

            session.execute(INSERT_TRIAGE, variable_values=variable_values)

        logger.debug(
            f"Inserted triage result for finding {finding_id}",
            decision=triage_result["decision"],
            explanation=triage_result["explanation"],
            confidence=triage_result["confidence"],
        )

    except Exception as e:
        logger.exception(e, message=f"Error inserting triage result for finding {finding_id}")
        raise


def extract_summary_from_triage_request(triage_request: TriageRequest) -> str | None:
    """
    Extract the summary from a TriageRequest's data field.

    Args:
        triage_request: The triage request containing finding data

    Returns:
        The summary string if found, None otherwise
    """
    if not triage_request.data or len(triage_request.data) == 0:
        return None

    first_data = triage_request.data[0]
    try:
        if isinstance(first_data, str):
            first_data = json.loads(first_data)
        if isinstance(first_data, dict) and "metadata" in first_data:
            return first_data["metadata"].get("summary")
    except json.JSONDecodeError:
        logger.error("Failed to parse finding data as JSON")

    return None


def handle_jwt_triage(ctx: DaprWorkflowContext, triage_request: TriageRequest, summary: str):
    """
    Handle JWT finding triage using rule-based validation.

    Checks if the summary contains JWT-specific markers and processes the finding
    with rule-based validation instead of LLM triage.

    Args:
        ctx: Dapr workflow context
        finding_id: The finding ID being triaged
        summary: The finding summary text
        file_path: Path to the file containing the JWT

    Returns:
        True if this is a JWT finding that was processed, False otherwise

    Yields:
        Workflow activity calls for JWT validation and result insertion
    """
    # Check if it's a JWT finding
    if triage_request.origin_name != "noseyparker":
        return False

    if not triage_request.raw_data:
        if not ctx.is_replaying:
            logger.warning(f"No raw_data available for noseyparker finding {triage_request.finding_id}")
        return False

    try:
        noseyparker_data = NoseyParkerData(**triage_request.raw_data)
    except Exception as e:
        if not ctx.is_replaying:
            logger.error(f"Failed to parse noseyparker data for finding {triage_request.finding_id}: {e}")
        return False

    # Check if this is specifically a JWT finding
    if noseyparker_data.match.rule_name != "JSON Web Token (base64url-encoded)":
        return False

    if not ctx.is_replaying:
        logger.info(f"Processing JWT finding {triage_request.finding_id} with rule-based triage")

    jwt_wrapper = agent_manager.get_wrapper_function("jwt")
    jwt_result = yield ctx.call_activity(
        jwt_wrapper,
        input={
            "summary": summary,
            "file_path": triage_request.file_path,
        },
    )

    result = TriageResult(
        finding_id=triage_request.finding_id,
        decision=jwt_result["decision"],
        explanation=jwt_result.get("explanation", "JWT validation completed"),
        confidence=1.0,
        true_positive_context=None,
        success=True,
    )

    yield ctx.call_activity(
        insert_triage_result,
        input={
            "finding_id": triage_request.finding_id,
            "triage_result": result.model_dump(),
        },
    )

    return True


@workflow_runtime.workflow
def finding_triage_workflow(ctx: DaprWorkflowContext, workflow_input: dict):
    """Main workflow for triaging findings."""
    try:
        # Parse workflow_input as TriageRequest
        triage_request = TriageRequest(**workflow_input)
        finding_id = triage_request.finding_id
        object_id = triage_request.object_id

        if not ctx.is_replaying:
            logger.info(f"Starting triage workflow for finding {finding_id}")

        # Step 1: Extract out the finding summary
        summary = extract_summary_from_triage_request(triage_request)

        if not summary:
            logger.warning(f"No summary found for finding {finding_id}")
            result = TriageResult(
                finding_id=finding_id,
                decision=TriageCategory.NOT_TRIAGED,
                explanation="No summary available",
                confidence=0.0,
                true_positive_context=None,
                success=False,
            )

            yield ctx.call_activity(
                insert_triage_result,
                input={
                    "finding_id": finding_id,
                    "triage_result": result.model_dump(),
                },
            )
            return

        file_path = triage_request.file_path

        # Step 2: Check if it's a JWT finding and handle non-LLM triage
        jwt_handled = yield from handle_jwt_triage(ctx, triage_request, summary)
        if jwt_handled:
            return

        # Step 3: Check for finding consensus:
        #         If we hit this number of the same triage values for the same file, all future findings get that value
        consensus_threshold = int(os.getenv("TRIAGE_CONSENSUS_THRESHOLD", 3))
        consensus = yield ctx.call_activity(
            check_consensus_activity,
            input={
                "object_id": object_id,
                "threshold": consensus_threshold,
            },
        )

        if consensus and consensus.get("has_consensus"):
            if not ctx.is_replaying:
                logger.info(
                    f"Using consensus triage for finding {finding_id}: {consensus['decision']} based on {consensus['count']} findings"
                )

            result = TriageResult(
                finding_id=finding_id,
                decision=consensus["decision"],
                explanation=f"Determined by existing {consensus['decision'].replace('_', ' ')} consensus for this file ({consensus['count']} findings)",
                confidence=1.0,
                true_positive_context=None,
                success=True,
            )

            yield ctx.call_activity(
                insert_triage_result,
                input={
                    "finding_id": finding_id,
                    "triage_result": result.model_dump(),
                },
            )
            return

        # Step 4: Use LLM validation agent if ModelManager has a model available
        if ModelManager.is_available():
            if not ctx.is_replaying:
                logger.info(f"Processing finding {finding_id} with AI validation")

            validate_wrapper = agent_manager.get_wrapper_function("validate")
            validation_result = yield ctx.call_activity(
                validate_wrapper,
                input={
                    "file_path": file_path,
                    "finding_id": finding_id,
                    "object_id": object_id,
                    "summary": summary,
                },
            )
            if not ctx.is_replaying:
                logger.debug(f"validation_result: {validation_result}")

            true_positive_context = ""
            if validation_result["decision"].lower() == "true_positive":
                true_positive_context = validation_result["true_positive_context"]

            result = TriageResult(
                finding_id=finding_id,
                decision=validation_result["decision"],
                explanation=validation_result["explanation"],
                confidence=validation_result["confidence"],
                true_positive_context=true_positive_context,
                success=True,
            )

            yield ctx.call_activity(
                insert_triage_result, input={"finding_id": finding_id, "triage_result": result.model_dump()}
            )
            return

        else:
            if not ctx.is_replaying:
                logger.warning("No LLM available for finding triage", finding_id=finding_id)

            return

    except Exception as e:
        logger.exception(e, message=f"Error in finding triage workflow for finding {finding_id}")


async def handle_findings_subscription():
    """Sets up and handles subscription to findings table in Hasura"""

    SUBSCRIPTION = gql("""
        subscription NewFindingIds {
            findings(
                where: {
                    triage_id: {_is_null: true},
                    category: {_nin: ["extracted_hash", "yara_match", "extracted_data"]},
                    finding_triage_histories_aggregate: {count: {predicate: {_eq: 0}}}
                },
                order_by: {created_at: desc}
            ) {
                finding_id
            }
        }
    """)

    while True:
        try:
            transport = WebsocketsTransport(
                url="ws://hasura:8080/v1/graphql",
                headers={"x-hasura-admin-secret": hasura_admin_secret},
                connect_args={"max_size": 20 * 1024 * 1024},
            )

            async with Client(
                transport=transport,
                fetch_schema_from_transport=True,
            ) as session:
                async for result in session.subscribe(SUBSCRIPTION):
                    if result is None:
                        continue

                    findings_list = result.get("findings", [])

                    for finding in findings_list:
                        finding_id = finding["finding_id"]
                        logger.info(f"Processing finding ID: {finding_id}")

                        finding_details = await fetch_finding_details(session, finding_id)

                        if not finding_details:
                            continue

                        file_path = finding_details["files_enriched"]["path"]
                        object_id = finding_details["files_enriched"]["object_id"]

                        try:
                            # Convert data objects to JSON strings if they're dicts
                            data_strings = []
                            if finding_details.get("data"):
                                for item in finding_details["data"]:
                                    if isinstance(item, dict):
                                        data_strings.append(json.dumps(item))
                                    else:
                                        data_strings.append(str(item))

                            triage_request = TriageRequest(
                                finding_id=finding_id,
                                finding_name=finding_details["finding_name"],
                                category=finding_details["category"],
                                severity=finding_details["severity"],
                                object_id=object_id,
                                origin_type=finding_details["origin_type"],
                                origin_name=finding_details["origin_name"],
                                data=data_strings,
                                raw_data=finding_details["raw_data"],
                                file_path=file_path,
                            )

                            instance_id = f"agents-triage-{finding_id}"
                            workflow_client.schedule_new_workflow(
                                workflow=finding_triage_workflow,
                                instance_id=instance_id,
                                input=triage_request.model_dump(),
                            )

                            try:
                                state = workflow_client.wait_for_workflow_completion(
                                    instance_id=instance_id, timeout_in_seconds=(10 * 60)
                                )
                                if not state:
                                    logger.error("Workflow not found!", instance_id=instance_id)
                                elif state.runtime_status.name == "COMPLETED":
                                    logger.debug("Workflow completed", finding_id=finding_id, instance_id=instance_id)
                                else:
                                    logger.warning(
                                        f"Workflow failed! Status: {state.runtime_status.name}"
                                    )  # not expected
                            except TimeoutError:
                                logger.error("Workflow timed out", instance_id=instance_id)

                        except Exception as e:
                            logger.exception(e, message=f"Error running workflow for finding {finding_id}")

                        del finding_details

        except Exception as e:
            logger.exception(e, message="Error in findings subscription, reconnecting in 5 seconds...")
            await asyncio.sleep(5)


@app.get("/agents/metadata")
async def get_agents_metadata():
    """Get metadata for all available agents."""
    try:
        agents = agent_manager.get_agent_metadata()
        return {"agents": agents, "total_count": len(agents), "timestamp": datetime.now().isoformat()}
    except Exception as e:
        logger.exception(e, message="Error getting agent metadata")
        return {"agents": [], "total_count": 0, "error": str(e), "timestamp": datetime.now().isoformat()}


@app.get("/agents/spend-data")
async def get_llm_spend_data():
    """Get LiteLLM spend and token usage data."""
    try:
        # Get PostgreSQL connection URL from Dapr secret store
        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_URL")
            postgres_connection_url = secret.secret["POSTGRES_CONNECTION_URL"]

        # Modify connection URL to connect to litellm database instead of enrichment
        litellm_connection_string = postgres_connection_url.replace("/enrichment", "/litellm")

        # Connect to the litellm database and fetch spend data
        conn = await asyncpg.connect(litellm_connection_string)
        try:
            query = """
                SELECT
                    COALESCE(SUM(spend), 0) as total_spend,
                    COALESCE(SUM(total_tokens), 0) as total_tokens,
                    COALESCE(SUM(prompt_tokens), 0) as total_prompt_tokens,
                    COALESCE(SUM(completion_tokens), 0) as total_completion_tokens,
                    COUNT(*) as total_requests
                FROM "LiteLLM_SpendLogs"
            """
            result = await conn.fetchrow(query)
            import pprint

            pprint.pprint(result)

            return {
                "total_spend": float(result["total_spend"]),
                "total_tokens": int(result["total_tokens"]),
                "total_prompt_tokens": int(result["total_prompt_tokens"]),
                "total_completion_tokens": int(result["total_completion_tokens"]),
                "total_requests": int(result["total_requests"]),
                "timestamp": datetime.now().isoformat(),
            }
        finally:
            await conn.close()

    except Exception as e:
        logger.exception(e, message="Error getting LLM spend data")
        return {
            "total_spend": 0.0,
            "total_tokens": 0,
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_requests": 0,
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
        }


@app.post("/agents/text_summarizer")
def run_text_summarizer(request: dict):
    """Run text summarization on a file."""
    try:
        object_id = request.get("object_id")
        if not object_id:
            return {"success": False, "error": "object_id is required"}

        # Create a mock workflow context for compatibility
        mock_ctx = type("MockContext", (), {})()

        result = summarize_text(mock_ctx, {"object_id": object_id})
        return result

    except Exception as e:
        logger.exception(e, message="Error running text summarizer")
        return {"success": False, "error": str(e)}


@app.post("/agents/llm_credential_analysis")
def run_credential_analysis(request: dict):
    """Run credential analysis on a file."""
    try:
        object_id = request.get("object_id")
        if not object_id:
            return {"success": False, "error": "object_id is required"}

        # Create a mock workflow context for compatibility
        mock_ctx = type("MockContext", (), {})()

        result = analyze_credentials(mock_ctx, {"object_id": object_id})
        return result

    except Exception as e:
        logger.exception(e, message="Error running credential analysis")
        return {"success": False, "error": str(e)}


@app.post("/agents/dotnet_analysis")
def run_dotnet_analysis(request: dict):
    """Run .NET assembly analysis on a file."""
    try:
        object_id = request.get("object_id")
        if not object_id:
            return {"success": False, "error": "object_id is required"}

        # Create a mock workflow context for compatibility
        mock_ctx = type("MockContext", (), {})()

        result = analyze_dotnet_assembly(mock_ctx, {"object_id": object_id})
        return result

    except Exception as e:
        logger.exception(e, message="Error running .NET analysis")
        return {"success": False, "error": str(e)}


@app.post("/agents/translate")
def run_translation(request: dict):
    """Run text translation on a file."""
    try:
        object_id = request.get("object_id")
        if not object_id:
            return {"success": False, "error": "object_id is required"}

        target_language = request.get("target_language", "English")

        # Create a mock workflow context for compatibility
        mock_ctx = type("MockContext", (), {})()

        result = translate_text(mock_ctx, {"object_id": object_id, "target_language": target_language})
        return result

    except Exception as e:
        logger.exception(e, message="Error running translation")
        return {"success": False, "error": str(e)}


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def health_check():
    """Health check endpoint."""
    try:
        if not workflow_runtime or not workflow_client:
            return {"status": "unhealthy", "error": "Workflow runtime not initialized"}

        return {"status": "healthy"}

    except Exception as e:
        logger.exception(e, message="Health check failed")
        return {"status": "unhealthy", "error": str(e)}
