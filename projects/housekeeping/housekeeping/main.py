import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Optional

import psycopg
import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from common.storage import StorageMinio
from dapr.clients import DaprClient
from fastapi import FastAPI, Query
from pydantic import BaseModel

# Configure structured logging
logger = structlog.get_logger(module=__name__)

# Global variables
scheduler = AsyncIOScheduler()
is_initialized = False
storage = StorageMinio()

with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]


def get_db_connection():
    """Create and return a database connection using psycopg."""

    try:
        conn = psycopg.connect(postgres_connection_string)
        return conn
    except Exception as e:
        logger.exception(e, message="Failed to get database connection")
        raise


async def get_expired_object_ids(expiration_date: Optional[datetime] = None) -> List[str]:
    """
    Get a list of all object_ids from files, files_enriched, and files_enriched_dataset tables
    that have passed their expiration date.

    Args:
        expiration_date: Optional date to use for comparison instead of current datetime.
                         If None, current datetime is used.
                         If datetime.max, all objects will be considered expired.
    """
    try:
        conn = get_db_connection()

        # Use provided expiration date or current datetime
        comparison_date = expiration_date if expiration_date is not None else datetime.now()

        # Define the WHERE clause based on the expiration_date
        where_clause = "WHERE 1=1"  # Default to get all records if datetime.max
        params = tuple()

        if expiration_date != datetime.max:
            where_clause = "WHERE expiration < %s"
            params = (comparison_date,)

        # Get expired object_ids from the files table
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT object_id
                FROM files
                {where_clause}
                """,
                params,
            )
            expired_files = cur.fetchall()

            # Get expired object_ids from the files_enriched table
            cur.execute(
                f"""
                SELECT object_id
                FROM files_enriched
                {where_clause}
                """,
                params,
            )
            expired_files_enriched = cur.fetchall()

            # Get expired object_ids from the files_enriched_dataset table
            cur.execute(
                f"""
                SELECT object_id
                FROM files_enriched_dataset
                {where_clause}
                """,
                params,
            )
            expired_files_dataset = cur.fetchall()

        # Combine all object_ids
        all_expired_object_ids = set()
        for record in expired_files:
            all_expired_object_ids.add(str(record[0]))
        for record in expired_files_enriched:
            all_expired_object_ids.add(str(record[0]))
        for record in expired_files_dataset:
            all_expired_object_ids.add(str(record[0]))

        return list(all_expired_object_ids)
    except Exception as e:
        logger.exception(e, message="Error getting expired object IDs from database")
        return []
    finally:
        if conn:
            conn.close()


async def get_transform_object_ids(object_ids: List[str]) -> List[str]:
    """
    Get all transform_object_ids that relate to the given object_ids.
    """
    if not object_ids:
        return []

    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            # Get all transform_object_ids related to the expired object_ids
            cur.execute(
                """
                SELECT transform_object_id
                FROM transforms
                WHERE object_id = ANY(%s::uuid[])
                """,
                (object_ids,),
            )
            transform_records = cur.fetchall()

        # Extract and return the transform_object_ids
        transform_object_ids = [str(record[0]) for record in transform_records]
        return transform_object_ids
    except Exception as e:
        logger.exception(e, message="Error getting transform object IDs from database")
        return []
    finally:
        if conn:
            conn.close()


async def delete_database_entries(object_ids: List[str]) -> bool:
    """
    Delete expired entries from database tables.
    Return True if successful, False otherwise.
    """
    if not object_ids:
        return True

    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            # The CASCADE delete should handle related records in other tables due to the foreign key constraints
            # defined in the schema

            # Delete from files_enriched_dataset
            cur.execute(
                """
                DELETE FROM files_enriched_dataset
                WHERE object_id = ANY(%s::uuid[])
                """,
                (object_ids,),
            )

            # Delete from files_enriched (will cascade to transforms, enrichments, etc.)
            cur.execute(
                """
                DELETE FROM files_enriched
                WHERE object_id = ANY(%s::uuid[])
                """,
                (object_ids,),
            )

            # Delete from files
            cur.execute(
                """
                DELETE FROM files
                WHERE object_id = ANY(%s::uuid[])
                """,
                (object_ids,),
            )

        conn.commit()
        logger.info("Successfully deleted database entries", object_count=len(object_ids))
        return True
    except Exception as e:
        logger.exception(e, message="Error deleting database entries")
        return False
    finally:
        if conn:
            conn.close()


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

    # Check if the service is initialized
    if not is_initialized:
        logger.error("Cleanup job aborted - service not initialized")
        return

    try:
        # Step 1: Get expired object IDs from database using the provided expiration date
        expired_object_ids = await get_expired_object_ids(expiration_date)
        logger.info("Found expired objects", count=len(expired_object_ids))

        if not expired_object_ids:
            logger.info("No expired objects found, cleanup job completed")
            return

        # Step 2: Get related transform object IDs
        transform_object_ids = await get_transform_object_ids(expired_object_ids)
        logger.info("Found related transform objects", count=len(transform_object_ids))

        # Step 3: Combine all object IDs that need to be deleted from Minio
        all_object_ids = list(set(expired_object_ids + transform_object_ids))

        # Step 4: Delete objects from Minio using the StorageMinio instance
        deleted_count = storage.delete_objects(all_object_ids)
        logger.info("Deleted objects from Minio", count=deleted_count, total=len(all_object_ids))

        # Step 5: Delete database entries
        db_delete_success = await delete_database_entries(expired_object_ids)
        if db_delete_success:
            logger.info("Successfully completed cleanup job")
        else:
            logger.error("Failed to delete some database entries during cleanup job")

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
    asyncio.create_task(run_cleanup_job(expiration_date))

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
