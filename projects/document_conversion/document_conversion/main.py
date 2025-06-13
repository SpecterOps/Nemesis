import json
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Optional, List

import zipfile
import olefile
import msoffcrypto
import psycopg
import jpype
import jpype.imports
import requests
import structlog
from common.models import FileEnriched, Transform, CloudEvent, File
from common.state_helpers import get_file_enriched
from common.helpers import can_extract_plaintext, extract_all_strings, can_convert_to_pdf
from common.storage import StorageMinio
from dapr.ext.fastapi import DaprApp
from dapr.clients import DaprClient
from dapr.ext.workflow import WorkflowRuntime, DaprWorkflowClient, RetryPolicy, when_all, DaprWorkflowContext
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext
from dapr.ext.workflow.logger.options import LoggerOptions
from fastapi import FastAPI
import tempfile
from PyPDF2 import PdfReader

logger = structlog.get_logger(module=__name__)

storage = StorageMinio()
db_pool = None
workflow_client: DaprWorkflowClient = None

workflow_runtime = WorkflowRuntime(
    logger_options=LoggerOptions(
        log_level="INFO",
        log_handler=None,
        log_formatter=None,
    )
)

with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]


# Initialize Java Runtime and Tika
def init_tika():
    if not jpype.isJVMStarted():
        jpype.startJVM(classpath=["/tika-server-standard.jar"])
        # Create Tika instance using Java class directly
        Tika = jpype.JClass("org.apache.tika.Tika")
        File = jpype.JClass("java.io.File")
        return Tika(), File


tika, JavaFile = init_tika()

# Configuration
dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
gotenberg_url = f"http://localhost:{dapr_port}/v1.0/invoke/gotenberg/method/forms/libreoffice/convert"
# pdf_size_limit = 25000000 ## no longer used??
# plaintext_size_limit = 50000000 ## no longer used??


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events"""
    global db_pool, workflow_runtime, workflow_client
    try:
        # start the workflow runtime
        workflow_runtime.start()

        # Initialize workflow client
        workflow_client = DaprWorkflowClient()

    except Exception as e:
        logger.exception(e, message="Error initializing service")
        raise

    yield

    # Cleanup
    if workflow_runtime:
        workflow_runtime.shutdown()
    if jpype.isJVMStarted():
        jpype.shutdownJVM()


app = FastAPI(lifespan=lifespan)
dapr_app = DaprApp(app)


# Helpers


def should_process_file(file_enriched):
    """
    Determine if the file should be processed based on its metadata.

    Specifically, we check if a file doesn't have an originating_object_id (so is an original submission),
    or if it does does it have a nesting level, meaning it's derived from a container and NOT from
    some type of already processed transform (e.g., so we don't extract text from a PDF converted from an office doc).
    """
    return not file_enriched.originating_object_id or (
        file_enriched.originating_object_id and file_enriched.nesting_level and file_enriched.nesting_level > 0
    )


def is_pdf_encrypted(pdf_path):
    try:
        # Create a PDF reader object
        reader = PdfReader(pdf_path)

        # Check if the PDF is encrypted
        return reader.is_encrypted

    except Exception as e:
        print(f"Error checking PDF: {e}")
        return None


def check_office_encryption(file_path: str):
    """Check if an Office file is encrypted."""
    with open(file_path, "rb") as f:
        try:
            office_file = msoffcrypto.OfficeFile(f)
            return office_file.is_encrypted()
        except:
            return False


def check_rms_protected(file_path: str):
    """Check if a file is RMS protected by looking for the DRMEncryptedTransform folder"""
    try:
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            file_list = zip_ref.namelist()

            # Check for the specific folder path that indicates RMS protection
            for file in file_list:
                if "DRMEncryptedTransform" in file:
                    return True

    except:
        pass

    # Try OLE approach if ZIP check failed or returned False
    try:
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            if ole.exists("\x06DataSpaces/TransformInfo/DRMEncryptedTransform"):
                return True
            ole.close()
    except:
        pass

    return False


def is_encrypted_file(file_data: FileEnriched):
    """Uses the magic type to determine if the file is encrypted"""

    if "Security: 1" in file_data.magic_type or "CDFV2 Encrypted" in file_data.magic_type:
        return True

    with storage.download(file_data.object_id) as temp_file:
        if "pdf document" in file_data.magic_type.lower():
            pdf_is_encrypted = is_pdf_encrypted(temp_file.name)
            logger.debug(f"is_encrypted_file() pdf_is_encrypted: {pdf_is_encrypted}")
            return pdf_is_encrypted
        else:
            if check_office_encryption(temp_file.name) or check_rms_protected(temp_file.name):
                return True
    return False


# Workflow Activities


@workflow_runtime.activity
def store_transform(ctx, activity_input):
    """Store transform data in PostgreSQL."""
    try:
        file_enriched_object_id = activity_input["file_enriched"]["object_id"]
        transform = activity_input["transform"]
        transform_type = transform["type"]

        with psycopg.connect(postgres_connection_string) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                    VALUES (%s, %s, %s, %s)
                """,
                    (
                        file_enriched_object_id,
                        transform["type"],
                        transform["object_id"],
                        json.dumps(transform["metadata"]) if transform.get("metadata") else None,
                    ),
                )
            conn.commit()
        logger.debug(f"Stored {transform_type} transform", object_id=file_enriched_object_id)
    except Exception as e:
        logger.exception(e, message=f"Error storing {transform_type} transform")
        raise


@workflow_runtime.activity
def publish_file_message(ctx: WorkflowActivityContext, activity_input: dict):
    """Publish a new file message for the transform as a Dapr activity."""
    try:
        transform = Transform.model_validate(activity_input["transform"])
        file_enriched = FileEnriched.model_validate(activity_input["file_enriched"])

        new_file = File(
            object_id=transform.object_id,
            originating_object_id=file_enriched.object_id,
            agent_id=file_enriched.agent_id,
            project=file_enriched.project,
            timestamp=file_enriched.timestamp,
            expiration=file_enriched.expiration,
            path=f"{file_enriched.path}/{transform.metadata['file_name']}",
        )

        with DaprClient() as client:
            client.publish_event(
                pubsub_name="pubsub",
                topic_name="file",
                data=new_file.model_dump_json(),
                data_content_type="application/json",
            )

        logger.info(
            f"Published new file message for transform",
            new_object_id=transform.object_id,
            originating_object_id=file_enriched.object_id,
        )
    except Exception as e:
        logger.exception(e, message="Error publishing file message")
        raise


@workflow_runtime.activity
def extract_tika_text(ctx: WorkflowActivityContext, file_input: dict) -> Optional[dict]:
    """Extract text using Tika."""
    object_id = file_input.get("object_id")
    result = None

    try:
        file_enriched = FileEnriched.model_validate(file_input)

        if not can_extract_plaintext(file_enriched.mime_type):
            return None

        with storage.download(file_enriched.object_id) as temp_file:
            # Extract text using Tika
            java_file = JavaFile(temp_file.name)
            java_text = tika.parseToString(java_file)
            extracted_text = str(java_text)

            if not extracted_text:
                return None

            # Upload extracted text
            object_id = storage.upload(extracted_text.encode("utf-8"))

            transform = Transform(
                type="extracted_text",
                object_id=str(object_id),
                metadata={
                    "file_name": "extracted_plaintext.txt",
                    "display_type_in_dashboard": "monaco",
                    "display_title": "Extracted Plaintext",
                },
            )

            # Record success in database
            with psycopg.connect(postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE workflows
                        SET enrichments_success = array_append(enrichments_success, %s)
                        WHERE object_id = %s
                        """,
                        ("extract_tika_text", file_enriched.object_id),
                    )
                conn.commit()

            logger.debug("Text extracted to extracted_plaintext.txt with Tika", object_id=file_enriched.object_id)

            result = transform.model_dump()
            return result

    except Exception as e:
        logger.exception(e, message="Error in Tika text extraction", object_id=object_id)

        # Record failure in database
        try:
            with psycopg.connect(postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE workflows
                        SET enrichments_failure = array_append(enrichments_failure, %s)
                        WHERE object_id = %s
                        """,
                        (f"extract_tika_text:{str(e)[:100]}", object_id),
                    )
                conn.commit()
        except Exception as db_error:
            logger.error(f"Failed to update extract_tika_text failure in database: {str(db_error)}")

        raise


@workflow_runtime.activity
def extract_strings(ctx: WorkflowActivityContext, file_input: dict) -> Optional[dict]:
    """Extract strings from binary files."""
    object_id = file_input.get("object_id")
    result = None

    try:
        file_enriched = FileEnriched.model_validate(file_input)

        if file_enriched.is_container:
            return None

        with storage.download(file_enriched.object_id) as temp_file:
            all_strings = extract_all_strings(temp_file.name)

            # Filter out null/empty strings and check if we have any valid strings
            valid_strings = [s for s in all_strings if s and s.strip()]

            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_file:
                for line in valid_strings:
                    tmp_file.write(line + "\n")
                    tmp_file.flush()

                if os.path.getsize(tmp_file.name) == 0:
                    logger.info("Temporary strings file is empty", object_id=file_enriched.object_id)
                    return None

                object_id = storage.upload_file(tmp_file.name)

                transform = Transform(
                    type="extracted_strings",
                    object_id=str(object_id),
                    metadata={
                        "file_name": "strings.txt",
                        "display_type_in_dashboard": "monaco",
                        "display_title": "Strings",
                    },
                )

                # Record success in database
                with psycopg.connect(postgres_connection_string) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE workflows
                            SET enrichments_success = array_append(enrichments_success, %s)
                            WHERE object_id = %s
                            """,
                            ("extract_strings", file_enriched.object_id),
                        )
                    conn.commit()

                logger.warning("'strings' sucessfully extracted to strings.txt", object_id=file_enriched.object_id)

                result = transform.model_dump()
                return result

    except Exception as e:
        logger.exception(e, message="Error extracting strings", object_id=object_id)

        # Record failure in database
        try:
            with psycopg.connect(postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE workflows
                        SET enrichments_failure = array_append(enrichments_failure, %s)
                        WHERE object_id = %s
                        """,
                        (f"extract_strings:{str(e)[:100]}", object_id),
                    )
                conn.commit()
        except Exception as db_error:
            logger.error(f"Failed to update extract_strings module failure in database: {str(db_error)}")

        raise


@workflow_runtime.activity
def convert_to_pdf(ctx: WorkflowActivityContext, file_input: dict) -> Optional[dict]:
    """Convert file to PDF using Gotenberg."""
    object_id = file_input.get("object_id")
    result = None

    try:
        file_enriched = FileEnriched.model_validate(file_input)

        if not can_convert_to_pdf(file_enriched.file_name):
            return None

        # excel docs need to be shown in landscape
        landscape = f"{file_enriched.extension}".lower() in [
            ".xls",
            ".xlsb",
            ".xlsm",
            ".xlsx",
            ".xlt",
            ".xltm",
            ".xltx",
            ".xlw",
        ]

        with storage.download(file_enriched.object_id) as temp_file:
            temp_file_with_ext = f"{temp_file.name}.{file_enriched.extension}"
            os.rename(temp_file.name, temp_file_with_ext)

            try:
                with open(temp_file_with_ext, "rb") as file_data:
                    files = {"file": file_data}
                    data = {}

                    if landscape:
                        data["landscape"] = "true"

                    response = requests.post(gotenberg_url, files=files, data=data, timeout=180)

                    if response.status_code == 200:
                        object_id = storage.upload(response.content)

                        transform = Transform(
                            type="converted_pdf",
                            object_id=str(object_id),
                            metadata={
                                "file_name": f"{file_enriched.file_name}.pdf",
                                "display_type_in_dashboard": "pdf",
                                "display_title": "Converted PDF",
                            },
                        )

                        # Record success in database
                        with psycopg.connect(postgres_connection_string) as conn:
                            with conn.cursor() as cur:
                                cur.execute(
                                    """
                                    UPDATE workflows
                                    SET enrichments_success = array_append(enrichments_success, %s)
                                    WHERE object_id = %s
                                    """,
                                    ("convert_to_pdf", file_enriched.object_id),
                                )
                            conn.commit()

                        logger.debug(
                            "File successfully converted to PDF with Gotenberg", object_id=file_enriched.object_id
                        )

                        result = transform.model_dump()
                        return result
                    else:
                        logger.error(
                            "Error calling Gotenberg",
                            status_code=response.status_code,
                            response_text=response.text,
                        )

                        # Record failure in database due to Gotenberg error
                        with psycopg.connect(postgres_connection_string) as conn:
                            with conn.cursor() as cur:
                                cur.execute(
                                    """
                                    UPDATE workflows
                                    SET enrichments_failure = array_append(enrichments_failure, %s)
                                    WHERE object_id = %s
                                    """,
                                    (
                                        f"convert_to_pdf:Gotenberg returned status code {response.status_code}",
                                        file_enriched.object_id,
                                    ),
                                )
                            conn.commit()

                        return None

            finally:
                os.rename(temp_file_with_ext, temp_file.name)

    except Exception as e:
        logger.exception(e, message="Error in PDF conversion", object_id=object_id)

        # Record failure in database
        try:
            with psycopg.connect(postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE workflows
                        SET enrichments_failure = array_append(enrichments_failure, %s)
                        WHERE object_id = %s
                        """,
                        (f"convert_to_pdf:{str(e)[:100]}", object_id),
                    )
                conn.commit()
        except Exception as db_error:
            logger.error(f"Failed to update convert_to_pdf failure in database: {str(db_error)}")

        raise


@workflow_runtime.workflow
def document_conversion_workflow(ctx: DaprWorkflowContext, workflow_input: dict):
    """Main workflow for text extraction processing."""
    try:
        object_id = workflow_input["object_id"]
        file_enriched = get_file_enriched(object_id)

        # Define retry policy for extraction activities
        retry_policy = RetryPolicy(
            first_retry_interval=timedelta(seconds=10),
            max_retry_interval=timedelta(seconds=50),
            backoff_coefficient=2.0,
            max_number_of_attempts=3,
            retry_timeout=timedelta(minutes=10),
        )

        # Run all extraction methods in parallel
        parallel_tasks = [
            ctx.call_activity(
                extract_tika_text,
                input=file_enriched.model_dump(exclude_unset=True, mode="json"),
                retry_policy=retry_policy,
            ),
            ctx.call_activity(
                extract_strings,
                input=file_enriched.model_dump(exclude_unset=True, mode="json"),
                retry_policy=retry_policy,
            ),
            ctx.call_activity(
                convert_to_pdf,
                input=file_enriched.model_dump(exclude_unset=True, mode="json"),
                retry_policy=retry_policy,
            ),
        ]

        # Wait for all extraction tasks to complete
        results = yield when_all(parallel_tasks)

        valid_transforms = [result for result in results if result is not None]

        if valid_transforms:
            file_enriched_json = file_enriched.model_dump(exclude_unset=True, mode="json")

            # For each transform, create parallel tasks for storing and publishing
            store_and_publish_tasks = []
            for transform in valid_transforms:
                store_and_publish_tasks.append(
                    ctx.call_activity(
                        store_transform,
                        input={"file_enriched": file_enriched_json, "transform": transform},
                        retry_policy=retry_policy,
                    )
                )

                store_and_publish_tasks.append(
                    ctx.call_activity(
                        publish_file_message,
                        input={"file_enriched": file_enriched_json, "transform": transform},
                        retry_policy=retry_policy,
                    )
                )

            # Wait for all store and publish tasks to complete
            yield when_all(store_and_publish_tasks)

        return {"status": "completed", "transforms_count": len(valid_transforms)}

    except Exception as e:
        logger.exception(e, message="Error in text extraction workflow")
        raise


# Main handling code


@dapr_app.subscribe(pubsub="pubsub", topic="file_enriched")
async def handle_file_enriched(event: CloudEvent[FileEnriched]):
    """Handler for file_enriched events."""
    try:
        file_enriched = event.data
        logger.debug("Received file_enriched event", object_id=file_enriched.object_id)

        # If the file is plaintext, skip
        if file_enriched.is_plaintext:
            logger.debug(
                "Skipping document_conversion_workflow - file is already text",
                object_id=file_enriched.object_id,
                path=file_enriched.path,
            )
            return

        # If the file is an existing transform, skip
        if not should_process_file(file_enriched):
            logger.debug(
                "Skipping document_conversion_workflow - should_process_file()",
                object_id=file_enriched.object_id,
                path=file_enriched.path,
            )
            return

        # If the file is encrypted, skip
        if is_encrypted_file(file_enriched):
            logger.warning(
                "Skipping document_conversion_workflow - file is encrypted or protected",
                object_id=file_enriched.object_id,
                path=file_enriched.path,
            )
            return

        instance_id = f"text-extraction-{file_enriched.object_id}"
        workflow_client.schedule_new_workflow(
            workflow=document_conversion_workflow, instance_id=instance_id, input={"object_id": file_enriched.object_id}
        )

        logger.info("Started text extraction workflow", instance_id=instance_id)

    except Exception as e:
        logger.exception(e, message="Error handling file_enriched event")
        raise


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def health_check():
    """Health check endpoint."""
    try:
        if not db_pool:
            return {"status": "unhealthy", "error": "Database pool not initialized"}

        async with db_pool.acquire() as connection:
            await connection.execute("SELECT 1")

        if not jpype.isJVMStarted():
            return {"status": "unhealthy", "error": "JVM not started"}

        if not workflow_runtime or not workflow_client:
            return {"status": "unhealthy", "error": "Workflow runtime not initialized"}

        return {"status": "healthy"}

    except Exception as e:
        logger.exception(e, message="Health check failed")
        return {"status": "unhealthy", "error": str(e)}
