# src/workflow/controller.py
import asyncio
import os

import asyncpg
from common.logger import get_logger

from .workflow import reload_yara_rules
from .workflow_manager import WorkflowManager

logger = get_logger(__name__)


async def postgres_notify_listener(asyncpg_pool: asyncpg.Pool, workflow_manager: WorkflowManager) -> None:
    """
    Listen for PostgreSQL NOTIFY events for yara reload and workflow reset.
    Runs in background task to handle notifications across all workers/replicas.
    """

    logger.info("Starting PostgreSQL NOTIFY listener...", pid=os.getppid())

    retry_delay = 1  # Start with 1 second retry delay
    max_retry_delay = 60  # Max 60 seconds between retries

    while True:
        conn = None
        try:
            # Acquire a dedicated connection from the pool for listening
            conn = await asyncpg_pool.acquire()
            logger.info("Connected to PostgreSQL for NOTIFY listening", pid=os.getppid())
            retry_delay = 1  # Reset retry delay on successful connection

            # Create a queue to receive notifications
            notification_queue = asyncio.Queue()

            # Callback function to handle notifications
            def notification_handler(connection, pid, channel, payload):
                try:
                    notification_queue.put_nowait((channel, payload))
                except Exception as e:
                    logger.error("Error queuing notification", error=str(e))

            # Add listeners for our notification channels
            await conn.add_listener("nemesis_yara_reload", notification_handler)
            await conn.add_listener("nemesis_workflow_reset", notification_handler)

            logger.info(
                "Listening for PostgreSQL notifications on nemesis_yara_reload and nemesis_workflow_reset",
                pid=os.getppid(),
            )

            # Process notifications
            try:
                while True:
                    try:
                        # Wait for notification with timeout to allow for cancellation checks
                        channel, payload = await asyncio.wait_for(notification_queue.get(), timeout=5.0)

                        logger.info(
                            f"Received PostgreSQL notification: channel={channel}, payload={payload}, pid={os.getpid()}"
                        )

                        if channel == "nemesis_yara_reload":
                            logger.info("Processing yara reload notification", pid=os.getppid())
                            reload_yara_rules()

                        elif channel == "nemesis_workflow_reset":
                            logger.info("Processing workflow reset notification", pid=os.getppid())
                            if workflow_manager is not None:
                                result = await workflow_manager.reset()
                                logger.info("Workflow manager reset completed", result=result)
                            else:
                                logger.warning("Workflow manager not initialized, skipping reset")

                    except asyncio.TimeoutError:
                        # No notification received, continue listening
                        continue
                    except Exception as e:
                        logger.exception(
                            "Error processing PostgreSQL notification",
                            error=str(e),
                            pid=os.getpid(),
                        )
            except asyncio.CancelledError:
                logger.info("PostgreSQL NOTIFY listener cancelled", pid=os.getppid())
                # Remove listeners before breaking
                try:
                    await conn.remove_listener("nemesis_yara_reload", notification_handler)
                    await conn.remove_listener("nemesis_workflow_reset", notification_handler)
                except Exception:
                    pass
                break

        except asyncio.CancelledError:
            logger.info("PostgreSQL NOTIFY listener cancelled during connection", pid=os.getppid())
            break
        except Exception as e:
            logger.exception("PostgreSQL NOTIFY listener connection error", error=str(e), pid=os.getppid())

            # Exponential backoff with jitter
            await asyncio.sleep(retry_delay + (retry_delay * 0.1))  # Add 10% jitter
            retry_delay = min(retry_delay * 2, max_retry_delay)

            logger.info(f"Retrying PostgreSQL NOTIFY listener in {retry_delay} seconds...", pid=os.getppid())
        finally:
            # Always release the connection back to the pool
            if conn is not None:
                try:
                    await asyncpg_pool.release(conn)
                    logger.debug("Released PostgreSQL connection back to pool", pid=os.getppid())
                except Exception as e:
                    logger.error("Error releasing connection to pool", error=str(e), pid=os.getppid())
