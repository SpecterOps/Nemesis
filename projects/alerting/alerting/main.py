import asyncio
import os
import re
from contextlib import asynccontextmanager

import apprise
from common.logger import get_logger
from common.models import Alert, CloudEvent
from dapr.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from fastapi import FastAPI, HTTPException
from gql import Client, gql
from gql.transport.websockets import WebsocketsTransport
from pydantic import BaseModel

logger = get_logger(__name__)
apobj = apprise.Apprise()
is_initialized = False

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events"""
    global is_initialized

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

        # Start feedback subscription
        subscription_task = asyncio.create_task(handle_feedback_subscription())
        logger.info("Started feedback subscription handler")

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

        # Only process Slack URLs
        if url.startswith("slack://"):
            # Extract channel name from Slack URL format: slack://TOKEN@WORKSPACE/#channel
            import re
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
