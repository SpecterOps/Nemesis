import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime

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
db_pool = None


async def get_db_pool():
    """Get the global database connection pool."""
    global db_pool
    if db_pool is None:
        raise RuntimeError("Database pool not initialized")
    return db_pool


async def get_expired_object_ids(expiration_date: datetime | None = None) -> list[str]:
    """
    Get a list of all object_ids from files, files_enriched, and files_enriched_dataset tables
    that have passed their expiration date.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all objects will be considered expired.
    """
    try:
        pool = await get_db_pool()
        comparison_date = expiration_date if expiration_date is not None else datetime.now()

        async with pool.acquire() as conn:
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


async def get_transform_object_ids(object_ids: list[str]) -> list[str]:
    """
    Get all transform_object_ids that relate to the given object_ids.
    """
    if not object_ids:
        return []

    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
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


async def delete_database_entries(object_ids: list[str]) -> bool:
    """
    Delete expired entries from database tables.
    Return True if successful, False otherwise.
    """
    if not object_ids:
        return True

    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
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

            logger.info(
                "Successfully deleted database entries",
                object_count=len(object_ids),
            )
            return True
    except Exception as e:
        logger.exception(e, message="Error deleting database entries")
        return False


async def delete_expired_chromium_data(expiration_date: datetime | None = None) -> bool:
    """
    Delete chromium data only when expiration_date is datetime.max (delete all mode).
    Otherwise, CASCADE deletion handles chromium data when files are deleted.

    Args:
        expiration_date: Optional date to use for comparison.
                         Only deletes if expiration_date == datetime.max.

    Returns:
        bool: True if successful, False otherwise.
    """
    # Only delete chromium data in "delete all" mode
    if expiration_date != datetime.max:
        # TODO: Delete based on expiration timestamp (currently not in the schema)
        logger.info("Skipping chromium deletion - CASCADE will handle expired entries")
        return True

    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
            # Delete all records from chromium tables in a transaction
            async with conn.transaction():
                await conn.execute("DELETE FROM chromium.history")
                await conn.execute("DELETE FROM chromium.downloads")
                await conn.execute("DELETE FROM chromium.state_keys")
                await conn.execute("DELETE FROM chromium.chrome_keys")
                await conn.execute("DELETE FROM chromium.logins")
                await conn.execute("DELETE FROM chromium.cookies")

            logger.info("Successfully deleted all chromium data")
            return True

    except Exception as e:
        logger.exception(e, message="Error deleting chromium data")
        return False


async def delete_expired_file_listings(expiration_date: datetime | None = None) -> bool:
    """
    Delete expired entries from the file_listings table based on their created_at timestamp.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all file_listings will be considered expired.

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
            # Use provided expiration date or current datetime
            comparison_date = expiration_date if expiration_date is not None else datetime.now()

            # Use DELETE...RETURNING to get count in a single query
            if expiration_date != datetime.max:
                deleted_records = await conn.fetch(
                    """
                    DELETE FROM file_listings
                    WHERE created_at < $1
                    RETURNING listing_id
                    """,
                    comparison_date,
                )
            else:
                deleted_records = await conn.fetch(
                    """
                    DELETE FROM file_listings
                    RETURNING listing_id
                    """
                )

            count_result = len(deleted_records)

            if count_result == 0:
                logger.info("No expired file_listings found to delete")
                return True

            logger.info(
                "Successfully deleted expired file_listings",
                file_listings_count=count_result,
                expiration_date=comparison_date if expiration_date != datetime.max else "all",
            )
            return True

    except Exception as e:
        logger.exception(e, message="Error deleting expired file_listings")
        return False


async def delete_expired_file_linkings(expiration_date: datetime | None = None) -> bool:
    """
    Delete expired entries from the file_linkings table based on their created_at timestamp.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all file_linkings will be considered expired.

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
            # Use provided expiration date or current datetime
            comparison_date = expiration_date if expiration_date is not None else datetime.now()

            # Use DELETE...RETURNING to get count in a single query
            if expiration_date != datetime.max:
                deleted_records = await conn.fetch(
                    """
                    DELETE FROM file_linkings
                    WHERE created_at < $1
                    RETURNING linking_id
                    """,
                    comparison_date,
                )
            else:
                deleted_records = await conn.fetch(
                    """
                    DELETE FROM file_linkings
                    RETURNING linking_id
                    """
                )

            count_result = len(deleted_records)

            if count_result == 0:
                logger.info("No expired file_linkings found to delete")
                return True

            logger.info(
                "Successfully deleted expired file_linkings",
                file_linkings_count=count_result,
                expiration_date=comparison_date if expiration_date != datetime.max else "all",
            )
            return True

    except Exception as e:
        logger.exception(e, message="Error deleting expired file_linkings")
        return False


async def delete_expired_dpapi_data(expiration_date: datetime | None = None) -> bool:
    """
    Delete expired entries from the dpapi tables based on their created_at timestamp.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all dpapi data will be considered expired.

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
            # Use provided expiration date or current datetime
            comparison_date = expiration_date if expiration_date is not None else datetime.now()

            # Delete all dpapi tables in a transaction
            async with conn.transaction():
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


async def delete_expired_containers(expiration_date: datetime | None = None) -> bool:
    """
    Delete expired entries from the container_processing table.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all containers will be considered expired.

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
            # Use provided expiration date or current datetime
            comparison_date = expiration_date if expiration_date is not None else datetime.now()

            # Use DELETE...RETURNING to get count in a single query
            if expiration_date != datetime.max:
                deleted_records = await conn.fetch(
                    """
                    DELETE FROM container_processing
                    WHERE expiration < $1
                    RETURNING container_id
                    """,
                    comparison_date,
                )
            else:
                deleted_records = await conn.fetch(
                    """
                    DELETE FROM container_processing
                    RETURNING container_id
                    """
                )

            count_result = len(deleted_records)

            if count_result == 0:
                logger.info("No expired containers found to delete")
                return True

            logger.info(
                "Successfully deleted expired containers",
                container_count=count_result,
                expiration_date=comparison_date if expiration_date != datetime.max else "all",
            )
            return True

    except Exception as e:
        logger.exception(e, message="Error deleting expired containers")
        return False


def _log_cleanup_result(result, success_msg: str, error_msg: str, round_num: int):
    """Helper function to log cleanup operation results."""
    if isinstance(result, Exception):
        logger.exception(result, message=error_msg)
    elif result:
        logger.info(success_msg, round=round_num)
    else:
        logger.error(error_msg, round=round_num)


_CLEANUP_RETRY_COUNT = 3
_CLEANUP_RETRY_DELAY = 20

async def run_cleanup_job(expiration_date: datetime | None = None):
    """
    Main job function that runs the cleanup process.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all objects will be considered expired.
    """
    global storage, is_initialized

    # TODO: Purge Dapr workflow state data either through the Dapr API (purge) or directly in the DB's "state" table.

    logger.info("Starting cleanup job", custom_expiration=expiration_date is not None, expiration_date=expiration_date)

    if not is_initialized:
        logger.error("Cleanup job aborted - service not initialized")
        return

    try:
        # Run cleanup three times over a minute to catch processing edge cases
        for round_num in range(0, _CLEANUP_RETRY_COUNT):
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
            # db_result, container_result, dpapi_result, chromium_result, file_listings_result, file_linkings_result = await asyncio.gather(
            #     delete_database_entries(expired_object_ids),
            #     delete_expired_containers(expiration_date),
            #     delete_expired_dpapi_data(expiration_date),
            #     delete_expired_chromium_data(expiration_date),
            #     delete_expired_file_listings(expiration_date),
            #     delete_expired_file_linkings(expiration_date),
            #     return_exceptions=True,
            # )

            db_result, container_result = await asyncio.gather(
                delete_database_entries(expired_object_ids),
                delete_expired_containers(expiration_date),
                return_exceptions=True,
            )

            # Log results
            _log_cleanup_result(db_result, "Successfully deleted database entries", "Failed to delete database entries", round_num)
            _log_cleanup_result(container_result, "Successfully deleted container entries", "Failed to delete container entries", round_num)
            # _log_cleanup_result(dpapi_result, "Successfully deleted dpapi data", "Failed to delete dpapi data", round_num)
            # _log_cleanup_result(chromium_result, "Successfully deleted chromium data", "Failed to delete chromium data", round_num)
            # _log_cleanup_result(file_listings_result, "Successfully deleted file_listings", "Failed to delete file_listings", round_num)
            # _log_cleanup_result(file_linkings_result, "Successfully deleted file_linkings", "Failed to delete file_linkings", round_num)

            logger.info(f"Cleanup job round {round_num} complete")

            if round_num < _CLEANUP_RETRY_COUNT - 1:
                logger.info(f"Waiting {_CLEANUP_RETRY_DELAY} seconds before next cleanup round")
                await asyncio.sleep(_CLEANUP_RETRY_DELAY)

        logger.info("Cleanup completed!")

    except Exception as e:
        logger.exception(e, message="Error running cleanup job")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events"""
    global storage, scheduler, is_initialized, db_pool

    try:
        logger.info("Initializing Housekeeping Service")

        # Initialize database connection pool
        db_pool = await asyncpg.create_pool(
            get_postgres_connection_str(),
            min_size=2,
            max_size=10,
            command_timeout=60,
        )
        logger.info("Database connection pool initialized", min_size=2, max_size=10)

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

        # Close database connection pool
        if db_pool:
            await db_pool.close()
            logger.info("Database connection pool closed")

    except Exception as e:
        logger.exception(e, message="Error during service initialization")
        raise


# Create model for trigger request
class CleanupRequest(BaseModel):
    # None means use current datetime, "all" means clean everything
    expiration: str | None = None


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
