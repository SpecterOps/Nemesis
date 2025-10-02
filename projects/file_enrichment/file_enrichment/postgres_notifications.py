# src/workflow/controller.py
import asyncio
import os

import psycopg
from common.logger import get_logger

from .workflow import reload_yara_rules
from .workflow_manager import WorkflowManager

logger = get_logger(__name__)


async def postgres_notify_listener(postgres_connection_string: str, workflow_manager: WorkflowManager) -> None:
    """
    Listen for PostgreSQL NOTIFY events for yara reload and workflow reset.
    Runs in background task to handle notifications across all workers/replicas.
    """

    logger.info("Starting PostgreSQL NOTIFY listener...", pid=os.getppid())

    retry_delay = 1  # Start with 1 second retry delay
    max_retry_delay = 60  # Max 60 seconds between retries

    while True:
        try:
            # Use async connection for LISTEN
            async with await psycopg.AsyncConnection.connect(postgres_connection_string, autocommit=True) as conn:
                logger.info("Connected to PostgreSQL for NOTIFY listening", pid=os.getppid())
                retry_delay = 1  # Reset retry delay on successful connection

                # Listen to our notification channels
                await conn.execute("LISTEN nemesis_yara_reload")
                await conn.execute("LISTEN nemesis_workflow_reset")

                logger.info(
                    "Listening for PostgreSQL notifications on nemesis_yara_reload and nemesis_workflow_reset",
                    pid=os.getppid(),
                )

                # Process notifications with timeout to prevent hanging
                try:
                    async for notify in conn.notifies():
                        try:
                            logger.info(
                                f"Received PostgreSQL notification: channel={notify.channel}, payload={notify.payload}, pid={os.getpid()}"
                            )

                            if notify.channel == "nemesis_yara_reload":
                                logger.info("Processing yara reload notification", pid=os.getppid())
                                reload_yara_rules()

                            elif notify.channel == "nemesis_workflow_reset":
                                logger.info("Processing workflow reset notification", pid=os.getppid())
                                if workflow_manager is not None:
                                    result = await workflow_manager.reset()
                                    logger.info("Workflow manager reset completed", result=result)
                                else:
                                    logger.warning("Workflow manager not initialized, skipping reset")

                        except Exception as e:
                            logger.exception(
                                "Error processing PostgreSQL notification",
                                channel=notify.channel,
                                payload=notify.payload,
                                error=str(e),
                                pid=os.getpid(),
                            )
                except asyncio.CancelledError:
                    logger.info("PostgreSQL NOTIFY listener cancelled", pid=os.getppid())
                    break
                except Exception as e:
                    logger.exception("Error in notification loop", error=str(e), pid=os.getpid())
                    raise

        except Exception as e:
            logger.exception("PostgreSQL NOTIFY listener connection error", error=str(e), pid=os.getppid())

            # Exponential backoff with jitter
            await asyncio.sleep(retry_delay + (retry_delay * 0.1))  # Add 10% jitter
            retry_delay = min(retry_delay * 2, max_retry_delay)

            logger.info(f"Retrying PostgreSQL NOTIFY listener in {retry_delay} seconds...", pid=os.getppid())
