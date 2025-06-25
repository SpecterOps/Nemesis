import asyncio
import json
import os
from contextlib import asynccontextmanager
from enum import Enum

import rigging as rg
import structlog
from common.storage import StorageMinio
from dapr.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from fastapi import FastAPI
from gql import Client, gql
from gql.transport.websockets import WebsocketsTransport

logger = structlog.get_logger(module=__name__)
storage = StorageMinio()


# Define triage categories
class TriageCategory(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    NOT_TRIAGED = "not_triaged"
    ERROR = "error"


# Get Hasura admin secret from Dapr secret store
with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="HASURA_ADMIN_SECRET")
    hasura_admin_secret = secret.secret["HASURA_ADMIN_SECRET"]
    logger.info("[triage] HASURA_ADMIN_SECRET retrieved")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events"""

    try:
        # Check if rigging generator config is available
        rigging_generator = os.getenv("RIGGING_GENERATOR_TRIAGE")
        if not rigging_generator:
            logger.warning("RIGGING_GENERATOR_TRIAGE environment variable not set - triage analysis disabled")

        # Start findings subscription
        subscription_task = asyncio.create_task(handle_findings_subscription())
        logger.info("Started findings subscription handler")

        yield

    except Exception as e:
        logger.exception(e, message="Error initializing triage service")
        raise


app = FastAPI(lifespan=lifespan)
dapr_app = DaprApp(app)


async def triage_finding(file_path, object_id, finding_data):
    """
    Analyze the finding data with LLM to determine if it is a true positive,
    false positive, or needs_review.
    """

    try:
        # Extract the finding summary from the data
        # We expect at least one data item in the finding with a summary field
        summary = None
        if finding_data and isinstance(finding_data, list) and len(finding_data) > 0:
            first_data = finding_data[0]
            try:
                # Parse the data as JSON if it's a string
                if isinstance(first_data, str):
                    first_data = json.loads(first_data)

                # Extract summary from metadata
                if isinstance(first_data, dict) and "metadata" in first_data:
                    summary = first_data["metadata"].get("summary")
            except json.JSONDecodeError:
                logger.error(f"Failed to parse finding data as JSON: {first_data}")

        if not summary:
            logger.warning("No summary found in finding data, cannot triage")
            return TriageCategory.NOT_TRIAGED

        # any findings we can triage without an LLM
        if "np.jwt.1" in summary and "JWT Analysis" in summary:
            if "**Expired**: True" in summary:
                if "**Expired**: False" in summary:
                    return TriageCategory.TRUE_POSITIVE
                else:
                    return TriageCategory.FALSE_POSITIVE
            elif "**Expired**: False" in summary:
                return TriageCategory.FALSE_POSITIVE
            else:
                return TriageCategory.NEEDS_REVIEW

        rigging_generator = os.getenv("RIGGING_GENERATOR_TRIAGE")
        if not rigging_generator:
            # logger.warning("RIGGING_GENERATOR_TRIAGE not set, cannot triage finding with LLM")
            return TriageCategory.NOT_TRIAGED

        generator = rg.get_generator(rigging_generator)

        # Send the data to the LLM for analysis
        response = await generator.chat(
            [
                {
                    "role": "system",
                    "content": """You are a cybersecurity expert specializing in analyzing security findings.
                Your task is to triage security findings as either true positive, false positive, or needs review.

                A true positive is a finding that accurately identifies a genuine security issue and is not derived
                from test/mock data. A false positive is a finding that incorrectly identifies something as a security
                issue, such as being sample, test, or mock data, or being an incorrect match for a regular expression.
                Use needs_review when there is insufficient information to make a determination. Also use the file
                path when making your determination.

                Analyze the finding summary carefully and respond ONLY with one of three values, do not output any explanation or thought process:
                - true_positive
                - false_positive
                - needs_review
                """,
                },
                {
                    "role": "user",
                    "content": f"Please triage the following security finding derived from the file '{file_path}' (object_id={object_id}):\n\n{summary}",
                },
            ]
        ).run()

        # Extract the result from the response
        triage_result = response.last.content
        logger.debug(f"triage_result: {triage_result}")

        if triage_result:
            # Normalize the result to match our enum
            result = triage_result.strip().lower()

            if result.endswith("true_positive"):
                return TriageCategory.TRUE_POSITIVE
            elif result.endswith("false_positive"):
                return TriageCategory.FALSE_POSITIVE
            else:
                return TriageCategory.NEEDS_REVIEW
        else:
            logger.warning("No LLM triage result")
            return TriageCategory.NOT_TRIAGED

    except Exception as e:
        logger.exception(e, message="Error during LLM triage of finding")
        return TriageCategory.ERROR


async def fetch_finding_details(session, finding_id):
    """Fetch full details for a finding after receiving its ID from subscription"""
    FINDING_DETAILS_QUERY = gql("""
        query FindingDetails($finding_id: bigint!) {
            findings_by_pk(finding_id: $finding_id) {
                finding_name
                category
                severity
                object_id
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
    except Exception as e:
        logger.exception(e, message=f"Error fetching details for finding ID {finding_id}")
        return None


async def handle_findings_subscription():
    """Sets up and handles subscription to findings table in Hasura using a lightweight approach"""
    # Lightweight subscription that only returns finding_ids
    SUBSCRIPTION = gql("""
        subscription NewFindingIds {
            findings(
                where: {
                    finding_name: {_eq: "noseyparker_match"},
                    triage_id: {_is_null: true},
                    finding_triage_histories_aggregate: {count: {predicate: {_eq: 0}}}
                },
                order_by: {created_at: desc}
            ) {
                finding_id
            }
        }
    """)

    INSERT_TRIAGE = gql("""
        mutation InsertTriage($finding_id: bigint!, $username: String!, $value: String!, $automated: Boolean!) {
            insert_findings_triage_history_one(object: {
                finding_id: $finding_id,
                username: $username,
                value: $value,
                automated: $automated
            }) {
                id
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

                        # Fetch complete details for this finding
                        finding_details = await fetch_finding_details(session, finding_id)

                        if not finding_details:
                            continue

                        file_path = finding_details["files_enriched"]["path"]
                        object_id = finding_details["files_enriched"]["object_id"]

                        # Triage the finding using LLM
                        triage_category = await triage_finding(file_path, object_id, finding_details["data"])
                        if (
                            triage_category == TriageCategory.TRUE_POSITIVE
                            or triage_category == TriageCategory.FALSE_POSITIVE
                            or triage_category == TriageCategory.NEEDS_REVIEW
                        ):
                            # Insert triage record
                            await session.execute(
                                INSERT_TRIAGE,
                                variable_values={
                                    "finding_id": finding_id,
                                    "username": "llm_triage",
                                    "value": triage_category,
                                    "automated": True,
                                },
                            )

                            logger.info(f"Successfully triaged finding {finding_id} as {triage_category}")
                        else:
                            logger.warning(f"Unsuccessfully triaged finding {finding_id} as {triage_category}")

        except Exception as e:
            logger.exception(e, message="Error in findings subscription, reconnecting in 5 seconds...")
            await asyncio.sleep(5)


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthcheck():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}
