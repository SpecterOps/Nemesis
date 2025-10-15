import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import asyncpg
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from common.db import get_postgres_connection_str
from common.logger import get_logger
from common.storage import StorageMinio
from fastapi import FastAPI
from pydantic import BaseModel

logger = get_logger(__name__)

# Global variables
scheduler = AsyncIOScheduler()
is_initialized = False
storage = StorageMinio()
background_tasks = set()

postgres_connection_string = get_postgres_connection_str()


async def get_db_connection():
    """Create and return a database connection using asyncpg."""

    try:
        conn = await asyncpg.connect(postgres_connection_string)
        return conn
    except Exception as e:
        logger.exception(e, message="Failed to get database connection")
        raise


async def get_expired_object_ids(expiration_date: Optional[datetime] = None) -> list[str]:
    """
    Get a list of all object_ids from files, files_enriched, and files_enriched_dataset tables
    that have passed their expiration date.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all objects will be considered expired.
    """
    conn = None
    try:
        conn = await get_db_connection()
        comparison_date = expiration_date if expiration_date is not None else datetime.now()

        records = await conn.fetch(
            """
            SELECT DISTINCT object_id
            FROM (
                SELECT object_id FROM files WHERE expiration < $1
                UNION
                SELECT object_id FROM files_enriched WHERE expiration < $2
                UNION
                SELECT object_id FROM files_enriched_dataset WHERE expiration < $3
            ) AS expired
            """,
            comparison_date, comparison_date, comparison_date,
        )
        return [str(record["object_id"]) for record in records]

    except Exception as e:
        logger.exception(e, message="Error getting expired object IDs from database")
        return []
    finally:
        if conn:
            await conn.close()


async def get_transform_object_ids(object_ids: list[str]) -> list[str]:
    """
    Get all transform_object_ids that relate to the given object_ids.
    """
    if not object_ids:
        return []

    conn = None
    try:
        conn = await get_db_connection()
        # Get all transform_object_ids related to the expired object_ids
        transform_records = await conn.fetch(
            """
            SELECT transform_object_id
            FROM transforms
            WHERE object_id = ANY($1::uuid[])
            """,
            object_ids,
        )

        # Extract and return the transform_object_ids
        transform_object_ids = [str(record["transform_object_id"]) for record in transform_records]
        return transform_object_ids
    except Exception as e:
        logger.exception(e, message="Error getting transform object IDs from database")
        return []
    finally:
        if conn:
            await conn.close()


async def delete_database_entries(object_ids: list[str]) -> bool:
    """
    Delete expired entries from database tables.
    Return True if successful, False otherwise.
    """
    if not object_ids:
        return True

    conn = None
    try:
        conn = await get_db_connection()

        # Start a transaction
        async with conn.transaction():
            # The CASCADE delete should handle related records in other tables due to the foreign key constraints
            # defined in the schema

            # Delete from files_enriched_dataset
            await conn.execute(
                """
                DELETE FROM files_enriched_dataset
                WHERE object_id = ANY($1::uuid[])
                """,
                object_ids,
            )

            # Delete from files_enriched (will cascade to transforms, enrichments, etc.)
            await conn.execute(
                """
                DELETE FROM files_enriched
                WHERE object_id = ANY($1::uuid[])
                """,
                object_ids,
            )

            # Delete from files
            await conn.execute(
                """
                DELETE FROM files
                WHERE object_id = ANY($1::uuid[])
                """,
                object_ids,
            )

        logger.info("Successfully deleted database entries", object_count=len(object_ids))
        return True
    except Exception as e:
        logger.exception(e, message="Error deleting database entries")
        return False
    finally:
        if conn:
            await conn.close()


async def delete_expired_dpapi_data(expiration_date: Optional[datetime] = None) -> bool:
    """
    Delete expired entries from the dpapi tables based on their created_at timestamp.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all dpapi data will be considered expired.

    Returns:
        bool: True if successful, False otherwise.
    """
    conn = None
    try:
        conn = await get_db_connection()

        # Use provided expiration date or current datetime
        comparison_date = expiration_date if expiration_date is not None else datetime.now()

        # Define queries based on the expiration_date
        if expiration_date != datetime.max:
            # Delete dpapi.masterkeys
            await conn.execute(
                """
                DELETE FROM dpapi.masterkeys
                WHERE created_at < $1
                """,
                comparison_date,
            )

            # Delete dpapi.domain_backup_keys
            await conn.execute(
                """
                DELETE FROM dpapi.domain_backup_keys
                WHERE created_at < $1
                """,
                comparison_date,
            )

            # Delete dpapi.system_credentials
            await conn.execute(
                """
                DELETE FROM dpapi.system_credentials
                WHERE created_at < $1
                """,
                comparison_date,
            )
        else:
            # Delete all records from dpapi tables
            await conn.execute("DELETE FROM dpapi.masterkeys")
            await conn.execute("DELETE FROM dpapi.domain_backup_keys")
            await conn.execute("DELETE FROM dpapi.system_credentials")

        return True

    except Exception as e:
        logger.exception(e, message="Error deleting expired dpapi data")
        return False
    finally:
        if conn:
            await conn.close()


async def delete_expired_containers(expiration_date: Optional[datetime] = None) -> bool:
    """
    Delete expired entries from the container_processing table.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all containers will be considered expired.

    Returns:
        bool: True if successful, False otherwise.
    """
    conn = None
    try:
        conn = await get_db_connection()

        # Use provided expiration date or current datetime
        comparison_date = expiration_date if expiration_date is not None else datetime.now()

        # Define queries based on the expiration_date
        if expiration_date != datetime.max:
            # First, get count of records that will be deleted for logging
            count_result = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM container_processing
                WHERE expiration < $1
                """,
                comparison_date,
            )

            if count_result == 0:
                logger.info("No expired containers found to delete")
                return True

            # Delete expired entries from container_processing table
            await conn.execute(
                """
                DELETE FROM container_processing
                WHERE expiration < $1
                """,
                comparison_date,
            )
        else:
            # Delete all records
            count_result = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM container_processing
                """
            )

            if count_result == 0:
                logger.info("No expired containers found to delete")
                return True

            await conn.execute(
                """
                DELETE FROM container_processing
                """
            )

        logger.info(
            "Successfully deleted expired containers",
            container_count=count_result,
            expiration_date=comparison_date if expiration_date != datetime.max else "all",
        )
        return True

    except Exception as e:
        logger.exception(e, message="Error deleting expired containers")
        return False
    finally:
        if conn:
            await conn.close()


def _log_cleanup_result(result, success_msg: str, error_msg: str, round_num: int):
    """Helper function to log cleanup operation results."""
    if isinstance(result, Exception):
        logger.exception(result, message=error_msg)
    elif result:
        logger.info(success_msg, round=round_num)
    else:
        logger.error(error_msg, round=round_num)


async def run_cleanup_job(expiration_date: Optional[datetime] = None):
    """
    Main job function that runs the cleanup process.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all objects will be considered expired.
    """
    global storage, is_initialized

    logger.info("Starting cleanup job", custom_expiration=expiration_date is not None, expiration_date=expiration_date)

    if not is_initialized:
        logger.error("Cleanup job aborted - service not initialized")
        return

    try:
        # Run cleanup three times over a minute to catch processing edge cases
        for round_num in range(1, 4):
            # Get expired object IDs from database
            expired_object_ids = await get_expired_object_ids(expiration_date)
            logger.info("Found expired objects", count=len(expired_object_ids), round=round_num)

            # Process file objects if any were found
            if expired_object_ids:
                transform_object_ids = await get_transform_object_ids(expired_object_ids)
                logger.info("Found related transform objects", count=len(transform_object_ids), round=round_num)

                all_object_ids = list(set(expired_object_ids + transform_object_ids))
                deleted_count = storage.delete_objects(all_object_ids)
                logger.info("Deleted objects from Minio", count=deleted_count, total=len(all_object_ids), round=round_num)

            # Run database deletions in parallel
            logger.info("Starting parallel database cleanup operations", round=round_num)
            db_result, container_result, dpapi_result = await asyncio.gather(
                delete_database_entries(expired_object_ids),
                delete_expired_containers(expiration_date),
                delete_expired_dpapi_data(expiration_date),
                return_exceptions=True,
            )

            # Log results
            _log_cleanup_result(db_result, "Successfully deleted database entries", "Failed to delete database entries", round_num)
            _log_cleanup_result(container_result, "Successfully deleted container entries", "Failed to delete container entries", round_num)
            _log_cleanup_result(dpapi_result, "Successfully deleted dpapi data", "Failed to delete dpapi data", round_num)

            await asyncio.sleep(20)

        logger.info("Cleanup job complete")

    except Exception as e:
        logger.exception(e, message="Error running cleanup job")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events"""
    global storage, scheduler, is_initialized

    try:
        logger.info("Initializing Housekeeping Service")

        # Get the cron schedule from environment or use default (midnight every day)
        cron_schedule = os.getenv("CLEANUP_SCHEDULE", "0 0 * * *")

        # Schedule the job using a cron trigger
        scheduler.add_job(
            run_cleanup_job,
            CronTrigger.from_crontab(cron_schedule),
            id="cleanup_job",
            replace_existing=True,
        )

        # Start the scheduler
        scheduler.start()
        logger.info("Scheduler started", cron_schedule=cron_schedule)

        # Set initialization flag
        is_initialized = True

        yield

        # Cleanup on shutdown
        logger.info("Shutting down Housekeeping Service")

        # Shut down the scheduler
        if scheduler.running:
            scheduler.shutdown()
            logger.info("Scheduler shutdown")

    except Exception as e:
        logger.exception(e, message="Error during service initialization")
        raise


# Create model for trigger request
class CleanupRequest(BaseModel):
    # None means use current datetime, "all" means clean everything
    expiration: Optional[str] = None


# Create FastAPI application with lifespan handler
app = FastAPI(
    title="Housekeeping Service",
    description="Service for cleaning up expired files and database entries",
    version="0.1.0",
    lifespan=lifespan,
)


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthcheck():
    """
    Health check endpoint for Docker healthcheck.
    """
    return {"status": "healthy"}


@app.get("/")
async def root():
    """
    Root endpoint that shows service information.
    """
    return {
        "name": "Housekeeping Service",
        "version": "0.1.0",
        "status": "operational",
        "description": "Service for cleaning up expired files and database entries",
    }


@app.post("/trigger-cleanup")
async def trigger_cleanup(request: CleanupRequest):
    """
    Manually trigger the cleanup job.

    Optional parameters:
    - expiration: ISO formatted datetime string or "all" to remove all files
                  If not provided, current datetime is used
    """
    if not is_initialized:
        return {"message": "Service not initialized yet", "status": "error"}

    # Determine expiration date to use
    expiration_date = None  # Default: use current datetime

    if request.expiration:
        if request.expiration.lower() == "all":
            # Special case: use datetime.max to match all records
            expiration_date = datetime.max
            logger.info("Triggering cleanup with 'all' option - will remove ALL files")
        else:
            # Parse the provided ISO format datetime
            try:
                expiration_date = datetime.fromisoformat(request.expiration)
                logger.info(f"Triggering cleanup with custom expiration: {expiration_date}")
            except ValueError:
                return {
                    "message": "Invalid expiration format. Use ISO format (YYYY-MM-DDTHH:MM:SS) or 'all'",
                    "status": "error",
                }

    # Trigger the cleanup job with the specified expiration
    task = asyncio.create_task(run_cleanup_job(expiration_date))
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)

    return {
        "message": "Cleanup job triggered successfully",
        "expiration_mode": "all"
        if expiration_date == datetime.max
        else ("custom" if expiration_date else "current_datetime"),
    }


# Run this file directly for local testing
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
