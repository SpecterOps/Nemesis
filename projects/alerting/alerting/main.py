import asyncio
import os
import re
from contextlib import asynccontextmanager

import aiohttp
import apprise
import common.helpers as helpers
from common.logger import get_logger
from common.models import Alert, CloudEvent
from dapr.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from fastapi import FastAPI, HTTPException
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport
from gql.transport.websockets import WebsocketsTransport
from pydantic import BaseModel

logger = get_logger(__name__)
apobj = apprise.Apprise()
is_initialized = False

# Global alert settings
alert_settings = {
    "alerting_enabled": True,
    "minimum_severity": 4,
    "category_excluded": [],
    "category_included": [],
    "file_path_excluded_regex": [],
    "file_path_included_regex": [],
    "llm_triage_values_to_alert": ["true_positive"],
}

# LLM configuration
llm_enabled = False
LLM_EXCLUDED_CATEGORIES = ["extracted_hash", "yara_match", "extracted_data"]

# Alert pool configuration
MAX_CONCURRENT_ALERTS = int(os.getenv("MAX_CONCURRENT_ALERTS", "10"))
MAX_ALERT_RETRIES = int(os.getenv("MAX_ALERT_RETRIES", "5"))
RETRY_DELAY_SECONDS = int(os.getenv("RETRY_DELAY_SECONDS", "30"))

# Create a semaphore to limit concurrent alert processing
alert_semaphore = asyncio.Semaphore(MAX_CONCURRENT_ALERTS)

nemesis_url = os.getenv("NEMESIS_URL", "http://localhost/")
nemesis_url = f"{nemesis_url}/" if not nemesis_url.endswith("/") else nemesis_url


with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="HASURA_ADMIN_SECRET")
    hasura_admin_secret = secret.secret["HASURA_ADMIN_SECRET"]
    logger.info(f"[alerting] HASURA_ADMIN_SECRET: {hasura_admin_secret}")


def process_apprise_url(url):
    pattern = r"^(.*?)(?:\?tag=([^&]+))?$"

    match = re.match(pattern, url)
    if not match:
        return {"url": url.strip("'\""), "tag": "default"}

    return (match.group(1).strip("'\""), match.group(2))


async def check_llm_enabled():
    """Check if the agents service is available (LLM functionality enabled).

    Retries up to 5 times with 10-second delays to handle containers starting in different orders.
    """
    dapr_port = os.getenv("DAPR_HTTP_PORT", "3500")
    agents_health_url = f"http://localhost:{dapr_port}/v1.0/invoke/agents/method/healthz"

    max_retries = 3
    retry_delay = 10

    for attempt in range(1, max_retries + 1):
        try:
            # Try to reach agents service via Dapr
            async with aiohttp.ClientSession() as session:
                async with session.get(agents_health_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        logger.info("LLM functionality detected - agents service is available", attempt=attempt)
                        return True
                    else:
                        logger.info(
                            "Agents service responded with non-200 status",
                            status=response.status,
                            attempt=attempt,
                            max_retries=max_retries
                        )
        except Exception as e:
            logger.info(
                "LLM functionality not available - agents service not reachable",
                error=str(e),
                attempt=attempt,
                max_retries=max_retries
            )

        # If not the last attempt, wait before retrying
        if attempt < max_retries:
            logger.info(f"Waiting {retry_delay} seconds before retry...", attempt=attempt)
            await asyncio.sleep(retry_delay)

    logger.info("LLM functionality disabled - agents service not available after all retries")
    return False


async def load_alert_settings():
    """Load alert settings from database, creating defaults if none exist."""
    global alert_settings

    QUERY_SETTINGS = gql("""
        query GetAlertSettings {
            alert_settings(limit: 1) {
                alerting_enabled
                minimum_severity
                category_excluded
                category_included
                file_path_excluded_regex
                file_path_included_regex
                llm_triage_values_to_alert
            }
        }
    """)

    INSERT_DEFAULT_SETTINGS = gql("""
        mutation InsertDefaultSettings {
            insert_alert_settings_one(object: {
                id: 1,
                alerting_enabled: true,
                minimum_severity: 4,
                category_excluded: [],
                category_included: [],
                file_path_excluded_regex: [],
                file_path_included_regex: [],
                llm_triage_values_to_alert: ["true_positive"]
            }, on_conflict: {
                constraint: alert_settings_pkey,
                update_columns: []
            }) {
                id
            }
        }
    """)

    try:
        transport = RequestsHTTPTransport(
            url="http://hasura:8080/v1/graphql",
            headers={"x-hasura-admin-secret": hasura_admin_secret}
        )

        with Client(transport=transport, fetch_schema_from_transport=False) as session:
            # Try to fetch existing settings
            result = session.execute(QUERY_SETTINGS)
            settings_list = result.get("alert_settings", [])

            if not settings_list:
                # No settings exist, insert defaults
                logger.info("No alert settings found, creating defaults")
                session.execute(INSERT_DEFAULT_SETTINGS)
                # Fetch the newly created settings
                result = session.execute(QUERY_SETTINGS)
                settings_list = result.get("alert_settings", [])

            if settings_list:
                settings = settings_list[0]
                alert_settings.update({
                    "alerting_enabled": settings.get("alerting_enabled", True),
                    "minimum_severity": settings.get("minimum_severity", 4),
                    "category_excluded": settings.get("category_excluded", []),
                    "category_included": settings.get("category_included", []),
                    "file_path_excluded_regex": settings.get("file_path_excluded_regex", []),
                    "file_path_included_regex": settings.get("file_path_included_regex", []),
                    "llm_triage_values_to_alert": settings.get("llm_triage_values_to_alert", ["true_positive"]),
                })
                logger.info("Alert settings loaded", settings=alert_settings)
            else:
                logger.warning("Failed to load alert settings, using defaults")

    except Exception as e:
        logger.error("Error loading alert settings, using defaults", error=str(e))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events"""
    global is_initialized, llm_enabled

    try:
        apprise_urls = os.getenv("APPRISE_URLS", "")
        if apprise_urls:
            for apprise_url in apprise_urls.split(","):
                # make sure we grab a passed tag if one exists
                url, tag = process_apprise_url(apprise_url)
                if not tag:
                    tag = "default"
                logger.info(f"[alerting] adding Apprise URL: {url} (tag: {tag})")
                apobj.add(f"{url}?footer=no", tag=tag)
        else:
            # Use test endpoint as default when APPRISE_URLS is not configured
            logger.info("No APPRISE_URLS configured, using test endpoint as default")
            apobj.add("json://localhost:8000/test/alert?footer=no", tag="default")

        is_initialized = True

        # Check if LLM functionality is enabled
        llm_enabled = await check_llm_enabled()
        logger.info(f"LLM functionality: {'enabled' if llm_enabled else 'disabled'}")

        # Load alert settings from database
        await load_alert_settings()

        # Start alert settings subscription
        settings_subscription_task = asyncio.create_task(handle_alert_settings_subscription())
        logger.info("Started alert settings subscription handler")

        # Start feedback subscription
        feedback_subscription_task = asyncio.create_task(handle_feedback_subscription())
        logger.info("Started feedback subscription handler")

        # Start triage subscription if LLM is enabled
        if llm_enabled:
            triage_subscription_task = asyncio.create_task(handle_findings_triage_subscription())
            logger.info("Started findings triage subscription handler")

        logger.info(f"Alert rate limiter configured with {MAX_CONCURRENT_ALERTS} concurrent alerts")
        logger.info(f"Alert retry policy: {MAX_ALERT_RETRIES} retries with {RETRY_DELAY_SECONDS}s delay")

    except Exception as e:
        logger.exception(e, message="Error initializing Apprise")
        raise

    yield


app = FastAPI(lifespan=lifespan)
dapr_app = DaprApp(app)


class TestAlert(BaseModel):
    title: str | None = "Nemesis Alert"
    body: str
    service: str | None = None
    tag: str | None = None


async def handle_alert_settings_subscription():
    """Sets up and handles subscription to alert_settings table in Hasura"""
    global alert_settings

    SUBSCRIPTION = gql("""
        subscription AlertSettings {
            alert_settings {
                alerting_enabled
                minimum_severity
                category_excluded
                category_included
                file_path_excluded_regex
                file_path_included_regex
                llm_triage_values_to_alert
                updated_at
            }
        }
    """)

    while True:
        try:
            transport = WebsocketsTransport(
                url="ws://hasura:8080/v1/graphql",
                headers={"x-hasura-admin-secret": hasura_admin_secret}
            )

            async with Client(
                transport=transport,
                fetch_schema_from_transport=False,
            ) as session:
                async for result in session.subscribe(SUBSCRIPTION):
                    if result is None:
                        continue

                    settings_list = result.get("alert_settings", [])
                    if not settings_list:
                        continue

                    settings = settings_list[0]
                    alert_settings.update({
                        "alerting_enabled": settings.get("alerting_enabled", True),
                        "minimum_severity": settings.get("minimum_severity", 4),
                        "category_excluded": settings.get("category_excluded", []),
                        "category_included": settings.get("category_included", []),
                        "file_path_excluded_regex": settings.get("file_path_excluded_regex", []),
                        "file_path_included_regex": settings.get("file_path_included_regex", []),
                        "llm_triage_values_to_alert": settings.get("llm_triage_values_to_alert", ["true_positive"]),
                    })
                    logger.info("Alert settings updated", settings=alert_settings)

        except Exception as e:
            logger.exception(e, message="Error in alert settings subscription, reconnecting in 5 seconds...")
            await asyncio.sleep(5)


async def handle_feedback_subscription():
    """Sets up and handles subscription to files_feedback table in Hasura"""
    SUBSCRIPTION = gql("""
        subscription FilesFeedback {
            files_feedback(where: {alert_sent: {_eq: false}}) {
                object_id
                username
                automated
                missing_parser
                missing_file_viewer
                sensitive_info_not_detected
                timestamp
            }
        }
    """)

    UPDATE_ALERT_SENT = gql("""
        mutation UpdateAlertSent($object_id: uuid!) {
            update_files_feedback(
                where: {object_id: {_eq: $object_id}},
                _set: {alert_sent: true}
            ) {
                affected_rows
            }
        }
    """)

    while True:
        try:
            transport = WebsocketsTransport(
                url="ws://hasura:8080/v1/graphql",
                headers={"x-hasura-admin-secret": hasura_admin_secret}
            )

            async with Client(
                transport=transport,
                fetch_schema_from_transport=False,  # Disable schema fetching to avoid large payload
            ) as session:
                async for result in session.subscribe(SUBSCRIPTION):
                    if result is None:
                        continue

                    feedback_list = result.get("files_feedback", [])
                    if not feedback_list:
                        continue

                    feedback = feedback_list[0]

                    # Construct markdown message
                    message_parts = []
                    object_id = feedback["object_id"]
                    nemesis_file_url = f"{nemesis_url}files/{object_id}"
                    message_parts.append(f"*object_id:* <{nemesis_file_url}|{object_id}>")
                    message_parts.append(f"*user*: {feedback['username']}")

                    if feedback.get("missing_parser"):
                        message_parts.append("- 📄 Missing parser")
                    if feedback.get("missing_file_viewer"):
                        message_parts.append("- 👁️ Missing file viewer")
                    if feedback.get("sensitive_info_not_detected"):
                        message_parts.append("- 🔒 Sensitive information not detected")

                    # Join all parts with newlines
                    body = "\n".join(message_parts)

                    logger.info(f"Nemesis feedback: {body}")

                    # Create an Alert object and process it through the rate-limited handler
                    alert = Alert(title="Nemesis Feedback", body=body, tag="feedback", service="feedback")

                    # Use the send_alert function but handle the result specifically for feedback
                    success = await send_alert_with_retries(alert)

                    if success:
                        # Mark alert as sent in database
                        try:
                            await session.execute(
                                UPDATE_ALERT_SENT, variable_values={"object_id": feedback["object_id"]}
                            )
                        except Exception as e:
                            logger.error("Failed to update alert_sent status", error=str(e))
                    else:
                        logger.error("Failed to send feedback notification through Apprise after retries")

        except Exception as e:
            logger.exception(e, message="Error in feedback subscription, reconnecting in 5 seconds...")
            await asyncio.sleep(5)


async def handle_findings_triage_subscription():
    """Sets up and handles subscription to findings_triage_history table in Hasura for LLM-triaged findings."""
    global alert_settings

    SUBSCRIPTION = gql("""
        subscription FindingsTriage {
            findings_triage_history(
                where: {automated: {_eq: true}},
                order_by: {timestamp: desc}
            ) {
                id
                finding_id
                value
                explanation
                confidence
                true_positive_context
                timestamp
                finding {
                    finding_name
                    category
                    severity
                    data
                    origin_type
                    origin_name
                    files_enriched {
                        path
                        object_id
                    }
                }
            }
        }
    """)

    # Track which triage IDs we've already processed to avoid duplicates
    processed_triage_ids = set()

    while True:
        try:
            transport = WebsocketsTransport(
                url="ws://hasura:8080/v1/graphql",
                headers={"x-hasura-admin-secret": hasura_admin_secret}
            )

            async with Client(
                transport=transport,
                fetch_schema_from_transport=False,
            ) as session:
                async for result in session.subscribe(SUBSCRIPTION):
                    if result is None:
                        continue

                    triage_list = result.get("findings_triage_history", [])
                    if not triage_list:
                        continue

                    for triage in triage_list:
                        triage_id = triage["id"]

                        # Skip if we've already processed this triage
                        if triage_id in processed_triage_ids:
                            continue

                        triage_value = triage["value"]
                        llm_triage_values = alert_settings.get("llm_triage_values_to_alert", ["true_positive"])

                        # Only alert if triage value is in configured list
                        if triage_value not in llm_triage_values:
                            logger.debug(
                                f"Skipping alert for finding - triage value '{triage_value}' not in configured list",
                                finding_id=triage["finding_id"],
                                configured_values=llm_triage_values
                            )
                            processed_triage_ids.add(triage_id)
                            continue

                        finding = triage.get("finding")
                        if not finding:
                            logger.warning(f"No finding data for triage ID {triage_id}")
                            processed_triage_ids.add(triage_id)
                            continue

                        # Extract finding details
                        finding_name = finding.get("finding_name", "Unknown Finding")
                        category = finding.get("category")
                        severity = finding.get("severity")
                        origin_name = finding.get("origin_name")
                        file_enriched = finding.get("files_enriched")
                        file_path = file_enriched.get("path") if file_enriched else None

                        object_id = file_enriched.get("object_id") if file_enriched else None

                        # Build alert body using Slack markdown format
                        body_parts = []
                        if category and severity is not None:
                            body_parts.append(f"- *Category:* {category} / *Severity:* {severity}")
                        if file_path:
                            body_parts.append(f"- *File Path:* {helpers.sanitize_file_path(file_path)}")
                        if triage.get("confidence") is not None:
                            body_parts.append(f"- *Triage Value:* {triage_value} (*Confidence:* {triage['confidence']:.2f})")

                        # Add links to finding and file using Slack format
                        if object_id:
                            nemesis_finding_url = f"{nemesis_url}findings?object_id={object_id}"
                            nemesis_file_url = f"{nemesis_url}files?object_id={object_id}"
                            body_parts.append(f"*<{nemesis_finding_url}|View Finding in Nemesis>* / *<{nemesis_file_url}|View File in Nemesis>*")

                        body = "\n".join(body_parts)

                        # Create alert with all required fields for filtering
                        alert = Alert(
                            title=finding_name,
                            body=body,
                            service=origin_name,
                            category=category,
                            severity=severity,
                            file_path=file_path,
                        )

                        logger.info(
                            f"Processing LLM-triaged finding alert",
                            finding_id=triage["finding_id"],
                            triage_value=triage_value,
                            category=category,
                            severity=severity
                        )

                        # Send alert through normal filtering and rate limiting
                        await send_alert_with_retries(alert)

                        # Mark as processed
                        processed_triage_ids.add(triage_id)

        except Exception as e:
            logger.exception(e, message="Error in findings triage subscription, reconnecting in 5 seconds...")
            await asyncio.sleep(5)


@app.post("/test/alert")
async def test_alert(payload: dict):
    """Test endpoint that prints alert details to console"""
    # Log the raw payload
    print("\n=== RAW PAYLOAD RECEIVED ===")
    print(payload)
    print("=========================\n")
    try:
        # Extract fields from Apprise JSON payload
        title = payload.get("title", "Nemesis Alert")
        body = payload.get("body") or payload.get("message")
        if not body:
            raise HTTPException(status_code=400, detail="No body or message found in payload")

        # Convert to our internal format
        alert = TestAlert(
            title=title,
            body=body,
            service=payload.get("service"),
            tag=payload.get("tag"),
        )
        if alert.service:
            title = f"[{alert.service}] {title}"

        # Print alert details to console
        print("\n=== TEST ALERT RECEIVED ===")
        print(f"Title: {title}")
        print(f"Body: {body}")
        if payload.get("tag"):
            print(f"Tag: {payload['tag']}")
        print("=========================\n")

        return {"status": "success", "message": "Test alert received and printed"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


def should_filter_alert(alert: Alert) -> tuple[bool, str]:
    """
    Determine if an alert should be filtered based on current settings.

    Args:
        alert: The Alert object to check

    Returns:
        tuple: (should_filter: bool, reason: str)
               True if alert should be filtered (not sent), False if it should be sent
    """
    global alert_settings

    # Check if alerting is globally disabled
    if not alert_settings.get("alerting_enabled", True):
        return True, "Alerting is globally disabled"

    # Check severity threshold (only if severity is present)
    if alert.severity is not None:
        min_severity = alert_settings.get("minimum_severity", 4)
        if alert.severity < min_severity:
            return True, f"Severity {alert.severity} below minimum threshold {min_severity}"

    # Check category filters (only if category is present)
    if alert.category:
        category_included = alert_settings.get("category_included", [])
        category_excluded = alert_settings.get("category_excluded", [])

        # If category_included is not empty, only allow those categories
        if category_included and alert.category not in category_included:
            return True, f"Category '{alert.category}' not in included list"

        # Then apply exclusion list
        if alert.category in category_excluded:
            return True, f"Category '{alert.category}' is in excluded list"

    # Check file path regex filters (only if file_path is present)
    if alert.file_path:
        file_path_excluded_regexes = alert_settings.get("file_path_excluded_regex", [])
        file_path_included_regexes = alert_settings.get("file_path_included_regex", [])

        # If included regexes are set, file_path must match at least one
        if file_path_included_regexes:
            matched_any = False
            for pattern in file_path_included_regexes:
                logger.warning(f"file_path: {alert.file_path}, regex: {pattern}")
                if not pattern:  # Skip empty patterns
                    continue
                try:
                    if re.search(pattern, alert.file_path):
                        matched_any = True
                        break
                except re.error as e:
                    logger.error(f"Invalid included regex pattern: {pattern}", error=str(e))

            if not matched_any:
                return True, f"File path does not match any included regex patterns"

        # Then check excluded regexes - if any match, filter the alert
        if file_path_excluded_regexes:
            for pattern in file_path_excluded_regexes:
                if not pattern:  # Skip empty patterns
                    continue
                try:
                    if re.search(pattern, alert.file_path):
                        return True, f"File path matches excluded regex: {pattern}"
                except re.error as e:
                    logger.error(f"Invalid excluded regex pattern: {pattern}", error=str(e))

    # Alert passes all filters
    return False, "Alert passes all filters"


async def send_alert_with_retries(alert):
    """
    Send an alert with retry logic, respecting the semaphore limit.

    Args:
        alert: The Alert object to send

    Returns:
        bool: True if the alert was successfully sent, False otherwise
    """

    if not is_initialized:
        logger.error("Apprise services not yet initialized")
        return False

    # Check if alert should be filtered
    should_filter, reason = should_filter_alert(alert)

    if should_filter:
        logger.info(f"Alert filtered: {reason}", alert_title=alert.title)
        return False

    # Prepare the alert parameters
    title = alert.title
    if alert.service:
        title = f"[{alert.service}] {alert.title}"

    kwargs = {"body": alert.body, "title": title, "notify_type": apprise.NotifyType.WARNING}

    if alert.tag:
        kwargs["tag"] = alert.tag
    else:
        kwargs["tag"] = "default"

    # Acquire semaphore to limit concurrent alerts
    async with alert_semaphore:
        retry_count = 0
        while retry_count < MAX_ALERT_RETRIES:
            try:
                success = await apobj.async_notify(**kwargs)
                if success:
                    logger.info(f"Alert sent successfully: {title}")
                    return True

                retry_count += 1
                logger.warning(f"Failed to send alert, retrying ({retry_count}/{MAX_ALERT_RETRIES})", title=title)
                await asyncio.sleep(RETRY_DELAY_SECONDS)
            except Exception as e:
                retry_count += 1
                logger.error(
                    f"Error sending alert, retrying ({retry_count}/{MAX_ALERT_RETRIES})", error=str(e), title=title
                )
                await asyncio.sleep(RETRY_DELAY_SECONDS)

    logger.error(f"Failed to send alert after {MAX_ALERT_RETRIES} retries", title=title)
    return False


@dapr_app.subscribe(pubsub="pubsub", topic="alert")
async def handle_alert(event: CloudEvent[Alert]):
    """Handler for `alert` events."""
    try:
        alert = event.data
        if not alert.title:
            alert.title = "Nemesis Alert"

        # Process the alert through our rate-limited handler
        success = await send_alert_with_retries(alert)

        if not success:
            logger.error("Alert could not be delivered after maximum retries", alert_title=alert.title)

        return {}

    except Exception as e:
        logger.exception(e, message="Error processing alert event")
        raise


@app.get("/apprise-info")
async def get_apprise_info():
    """Get information about configured Apprise URLs, specifically Slack channels."""
    apprise_urls = os.getenv("APPRISE_URLS", "")

    if not apprise_urls:
        return {"channels": []}

    channels = []

    for apprise_url in apprise_urls.split(","):
        url, tag = process_apprise_url(apprise_url)

        # Only process Slack URLs for this status as we can pull the channel (if possible)
        if url.startswith("slack://"):
            # Extract channel name from Slack URL format: slack://TOKEN@WORKSPACE/#channel
            channel_match = re.search(r'#([^?]+)', url)
            if channel_match:
                channel_name = channel_match.group(1)

                if tag and tag != "default":
                    channels.append({
                        "name": channel_name,
                        "type": "tagged",
                        "tag": tag
                    })
                else:
                    channels.append({
                        "name": channel_name,
                        "type": "main"
                    })

    return {"channels": channels}


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthcheck():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}
