import asyncio
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID

import asyncpg
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from common.data_issues import DataIssueKind, log_data_issue
from common.db import get_postgres_connection_str
from common.logger import get_logger
from common.models2.api import ensure_utc_datetime
from common.storage import StorageS3
from fastapi import FastAPI
from pydantic import BaseModel

logger = get_logger(__name__)

# Global variables
scheduler = AsyncIOScheduler()
is_initialized = False
# Created at startup (lifespan): StorageS3 reads its credentials from Dapr, which isn't available at import time.
storage: StorageS3 | None = None
background_tasks = set()
db_pool = None


async def get_db_pool():
    """Get the global database connection pool."""
    global db_pool
    if db_pool is None:
        raise RuntimeError("Database pool not initialized")
    return db_pool


async def get_expired_object_ids(expiration_date: datetime | None = None) -> list[UUID]:
    """
    Get a list of all object_ids from the files and files_enriched tables that have passed their
    expiration date.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all objects will be considered expired.
    """
    try:
        pool = await get_db_pool()
        comparison_date = expiration_date if expiration_date is not None else datetime.now(UTC)

        async with pool.acquire() as conn:
            records = await conn.fetch(
                """
                SELECT DISTINCT object_id
                FROM (
                    SELECT object_id FROM files WHERE expiration < $1
                    UNION
                    SELECT object_id FROM files_enriched WHERE expiration < $1
                ) AS expired
                """,
                comparison_date,
            )
            return [record["object_id"] for record in records]

    except Exception:
        logger.exception(message="Error getting expired object IDs from database")
        return []


async def get_transform_object_map(object_ids: list[UUID]) -> dict[UUID, list[UUID]] | None:
    """
    Map each of the given object_ids to the transform_object_ids derived from it.

    Returns None if the lookup failed: deleting a file's rows without knowing its transforms would cascade away the
    transforms rows and orphan their storage objects, so callers must skip the round instead.
    """
    if not object_ids:
        return {}

    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
            transform_records = await conn.fetch(
                """
                SELECT object_id, transform_object_id
                FROM transforms
                WHERE object_id = ANY($1::uuid[])
                """,
                object_ids,
            )
        transform_map: dict[UUID, list[UUID]] = {}
        for record in transform_records:
            transform_map.setdefault(record["object_id"], []).append(record["transform_object_id"])
        return transform_map
    except Exception:
        logger.exception(message="Error getting transform object IDs from database")
        return None


def delete_expired_objects_from_storage(
    expired_object_ids: list[UUID], transform_map: dict[UUID, list[UUID]]
) -> tuple[list[UUID], list[UUID]]:
    """
    Delete the storage objects of expired files and their transforms.

    Returns (deletable, kept): an expired object_id is deletable from the database only when its own object and every
    transform object derived from it no longer exist in storage. The rest keep their database rows, so the next run
    finds them again and retries; deleting the rows would lose the only record of the objects.
    """
    if storage is None:
        raise RuntimeError("Storage not initialized")
    all_object_ids = list(dict.fromkeys(expired_object_ids + [t for ts in transform_map.values() for t in ts]))
    removed = storage.delete_objects_with_status(all_object_ids)
    deletable: list[UUID] = []
    kept: list[UUID] = []
    for object_id in expired_object_ids:
        related = [object_id, *transform_map.get(object_id, [])]
        (deletable if all(r in removed for r in related) else kept).append(object_id)
    return deletable, kept


async def delete_database_entries(object_ids: list[UUID]) -> bool:
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
    except Exception:
        logger.exception(message="Error deleting database entries")
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

    except Exception:
        logger.exception(message="Error deleting chromium data")
        return False


# file_listings and file_linkings have no expiration of their own: they describe a source (host) and only exist
# because files from that source were collected. They are deleted once no unexpired file from that source remains.
# (A created_at < now() rule would wipe every row on each nightly run.)
_SOURCE_HAS_LIVE_FILES = """
    EXISTS (SELECT 1 FROM files WHERE files.source = {table}.source AND files.expiration >= $1)
    OR EXISTS (SELECT 1 FROM files_enriched fe WHERE fe.source = {table}.source AND fe.expiration >= $1)
"""


async def delete_expired_file_listings(expiration_date: datetime | None = None) -> bool:
    """
    Delete file_listings rows whose source has no unexpired files left.

    Listings tied to a collected file (object_id) are also removed by ON DELETE CASCADE with that file; this removes
    the rest (paths still to be collected, not present, or not wanted).

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
            comparison_date = expiration_date if expiration_date is not None else datetime.now(UTC)

            # Use DELETE...RETURNING to get count in a single query
            if expiration_date != datetime.max:
                deleted_records = await conn.fetch(
                    f"""
                    DELETE FROM file_listings
                    WHERE NOT ({_SOURCE_HAS_LIVE_FILES.format(table="file_listings")})
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

    except Exception:
        logger.exception(message="Error deleting expired file_listings")
        return False


async def delete_expired_file_linkings(expiration_date: datetime | None = None) -> bool:
    """
    Delete file_linkings rows whose source has no unexpired files left (they hold file paths from that host).

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
            comparison_date = expiration_date if expiration_date is not None else datetime.now(UTC)

            # Use DELETE...RETURNING to get count in a single query
            if expiration_date != datetime.max:
                deleted_records = await conn.fetch(
                    f"""
                    DELETE FROM file_linkings
                    WHERE NOT ({_SOURCE_HAS_LIVE_FILES.format(table="file_linkings")})
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

    except Exception:
        logger.exception(message="Error deleting expired file_linkings")
        return False


async def delete_expired_dpapi_data(expiration_date: datetime | None = None) -> bool:
    """
    Delete a project's DPAPI masterkeys, domain backup keys and system credentials once it has no unexpired files.

    DPAPI rows are scoped to a project but record neither a source nor the file a key came from, and keys from one
    upload decrypt blobs from other uploads of the same project, so they cannot expire per file. A project's keys are
    kept while any of its files is still within its retention, and deleted (rows last updated before the comparison
    date) once all of them have expired. (A created_at < now() rule would delete every key on each nightly run while
    their files are still being analysed.)

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
            comparison_date = expiration_date if expiration_date is not None else datetime.now(UTC)

            # Delete all dpapi tables in a transaction
            async with conn.transaction():
                if expiration_date != datetime.max:
                    for table in ("dpapi.masterkeys", "dpapi.domain_backup_keys", "dpapi.system_credentials"):
                        result = await conn.execute(
                            f"""
                            DELETE FROM {table} d
                            WHERE d.updated_at < $1
                              AND NOT EXISTS (
                                  SELECT 1 FROM files f WHERE f.project = d.project AND f.expiration >= $1
                              )
                              AND NOT EXISTS (
                                  SELECT 1 FROM files_enriched fe WHERE fe.project = d.project AND fe.expiration >= $1
                              )
                            """,
                            comparison_date,
                        )
                        logger.info(
                            "Deleted DPAPI data of projects with no unexpired files", table=table, result=result
                        )
                else:
                    # Delete all records from dpapi tables
                    await conn.execute("DELETE FROM dpapi.masterkeys")
                    await conn.execute("DELETE FROM dpapi.domain_backup_keys")
                    await conn.execute("DELETE FROM dpapi.system_credentials")

            return True

    except Exception:
        logger.exception(message="Error deleting expired dpapi data")
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
            comparison_date = expiration_date if expiration_date is not None else datetime.now(UTC)

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

    except Exception:
        logger.exception(message="Error deleting expired containers")
        return False


def _log_cleanup_result(result, success_msg: str, error_msg: str, round_num: int):
    """Helper function to log cleanup operation results."""
    if isinstance(result, Exception):
        logger.exception(str(result), message=error_msg)
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

    logger.info("Starting cleanup job", custom_expiration=expiration_date is not None, expiration_date=expiration_date)

    if not is_initialized or storage is None:
        logger.error("Cleanup job aborted - service not initialized")
        return

    # Objects written after this point (uploads arriving during the job) are never swept.
    job_started = datetime.now(UTC)

    try:
        # Run cleanup three times over a minute to catch processing edge cases
        for round_num in range(0, _CLEANUP_RETRY_COUNT):
            # Get expired object IDs from database
            expired_object_ids = await get_expired_object_ids(expiration_date)
            logger.info("Found expired objects", count=len(expired_object_ids), round=round_num)

            # Delete storage first, then only the database rows whose objects are gone. A failed storage delete keeps
            # its rows (and so its object IDs) for the next run; a database failure after the storage delete is
            # retried too, because objects that are already absent count as deleted.
            deletable_object_ids: list[UUID] = []
            if expired_object_ids:
                transform_map = await get_transform_object_map(expired_object_ids)
                if transform_map is None:
                    logger.error("Skipping file deletion this round - transform lookup failed", round=round_num)
                else:
                    logger.info(
                        "Found related transform objects",
                        count=sum(len(t) for t in transform_map.values()),
                        round=round_num,
                    )
                    deletable_object_ids, kept_object_ids = await asyncio.to_thread(
                        delete_expired_objects_from_storage, expired_object_ids, transform_map
                    )
                    logger.info(
                        "Deleted objects from data lake",
                        files=len(deletable_object_ids),
                        total=len(expired_object_ids),
                        round=round_num,
                    )
                    if kept_object_ids:
                        logger.warning(
                            "Storage delete failed; keeping database rows for retry",
                            count=len(kept_object_ids),
                            round=round_num,
                        )

            # Run database deletions in parallel
            logger.info("Starting parallel database cleanup operations", round=round_num)
            (
                db_result,
                container_result,
                dpapi_result,
                chromium_result,
                file_listings_result,
                file_linkings_result,
            ) = await asyncio.gather(
                delete_database_entries(deletable_object_ids),
                delete_expired_containers(expiration_date),
                delete_expired_dpapi_data(expiration_date),
                delete_expired_chromium_data(expiration_date),
                delete_expired_file_listings(expiration_date),
                delete_expired_file_linkings(expiration_date),
                return_exceptions=True,
            )

            # Log results
            _log_cleanup_result(
                db_result, "Successfully deleted database entries", "Failed to delete database entries", round_num
            )
            _log_cleanup_result(
                container_result,
                "Successfully deleted container entries",
                "Failed to delete container entries",
                round_num,
            )
            _log_cleanup_result(
                dpapi_result, "Successfully deleted dpapi data", "Failed to delete dpapi data", round_num
            )
            _log_cleanup_result(
                chromium_result, "Successfully deleted chromium data", "Failed to delete chromium data", round_num
            )
            _log_cleanup_result(
                file_listings_result,
                "Successfully deleted file_listings",
                "Failed to delete file_listings",
                round_num,
            )
            _log_cleanup_result(
                file_linkings_result,
                "Successfully deleted file_linkings",
                "Failed to delete file_linkings",
                round_num,
            )

            logger.info(f"Cleanup job round {round_num} complete")

            if round_num < _CLEANUP_RETRY_COUNT - 1:
                logger.info(f"Waiting {_CLEANUP_RETRY_DELAY} seconds before next cleanup round")
                await asyncio.sleep(_CLEANUP_RETRY_DELAY)

        if expiration_date == datetime.max:
            # "all": also remove objects no database row points to any more (e.g. from failed deletes in earlier
            # versions, or uploads whose processing never recorded them). Only in this mode: an ordinary run can't
            # tell an orphan from a file still waiting in the processing queue.
            swept, sweep_failed = await asyncio.to_thread(storage.delete_objects_modified_before, job_started)
            logger.info("Swept remaining storage objects", deleted=swept, failed=sweep_failed)

        logger.info("Cleanup completed!")

    except Exception:
        logger.exception(message="Error running cleanup job")


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

        storage = StorageS3()

        # Get the cron schedule from environment or use default (midnight every day)
        cron_schedule = os.getenv("CLEANUP_SCHEDULE", "0 0 * * *")

        # Schedule the cleanup job using a cron trigger
        scheduler.add_job(
            run_cleanup_job,
            CronTrigger.from_crontab(cron_schedule),
            id="cleanup_job",
            replace_existing=True,
        )

        # Start the scheduler
        scheduler.start()
        logger.info(
            "Scheduler started",
            cleanup_schedule=cron_schedule,
        )

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

    except Exception:
        logger.exception(message="Error during service initialization")
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
            # Parse the provided ISO format datetime; it must carry a timezone (Z or an offset)
            try:
                expiration_date = ensure_utc_datetime(request.expiration)
                logger.info(f"Triggering cleanup with custom expiration: {expiration_date}")
            except ValueError as e:
                log_data_issue(
                    DataIssueKind.REJECTED_INPUT, field="cleanup.expiration", reason=str(e), value=request.expiration
                )
                return {
                    "message": "Invalid expiration format. Use an ISO datetime with a timezone "
                    "(YYYY-MM-DDTHH:MM:SSZ or +HH:MM) or 'all'",
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
