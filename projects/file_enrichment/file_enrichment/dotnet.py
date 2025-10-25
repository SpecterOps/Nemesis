# src/workflow/dotnet.py
import asyncio
import json
import uuid
from typing import Any

import psycopg
from common.helpers import sanitize_for_jsonb
from common.logger import get_logger
from common.models import (
    DotNetAssemblyAnalysis,
    EnrichmentResult,
    File,
    FileObject,
    Finding,
    FindingCategory,
    FindingOrigin,
    Transform,
)
from dapr.clients import DaprClient
from psycopg_pool import ConnectionPool

logger = get_logger(__name__)


def create_dotnet_finding_summary(analysis: DotNetAssemblyAnalysis) -> str:
    """
    Creates a markdown summary of DotNet assembly analysis findings.

    Args:
        analysis (DotNetAssemblyAnalysis): The assembly analysis results

    Returns:
        str: A markdown formatted summary of the findings
    """
    # Generate a finding ID (using a UUID)
    finding_id = str(uuid.uuid4())

    summary = f"# .NET Assembly Analysis: {analysis.AssemblyName}\n\n"
    summary += "### Metadata\n"
    summary += f"* **Finding ID**: {finding_id}\n"
    summary += f"* **Assembly Name**: {analysis.AssemblyName}\n"
    summary += f"* **WCF Server**: {analysis.IsWCFServer}\n"
    summary += f"* **WCF Client**: {analysis.IsWCFClient}\n\n"

    # Remoting channels
    if analysis.RemotingChannels:
        summary += "### Remoting Channels\n"
        for channel in analysis.RemotingChannels:
            summary += f"* {channel}\n"
        summary += "\n"

    # Helper function to add method calls section
    def add_method_section(title: str, method_dict: dict[str, list[Any]]):
        if method_dict:
            summary_content = f"### {title}\n"
            for category, methods in method_dict.items():
                if methods:
                    summary_content += f"\n#### {category}\n"
                    for method in methods:
                        if hasattr(method, "MethodName"):
                            summary_content += f"* **{method.MethodName}** (Level: {method.FilterLevel})\n"
                        else:
                            summary_content += f"* {method}\n"
            summary_content += "\n"
            return summary_content
        return ""

    # Add various method call sections
    summary += add_method_section("Serialization Gadget Calls", analysis.SerializationGadgetCalls)
    summary += add_method_section("WCF Server Calls", analysis.WcfServerCalls)
    summary += add_method_section("Client Calls", analysis.ClientCalls)
    summary += add_method_section("Remoting Calls", analysis.RemotingCalls)
    summary += add_method_section("Execution Calls", analysis.ExecutionCalls)

    return summary


async def store_dotnet_results(
    object_id: str,
    decompilation_object_id: str = None,
    analysis: DotNetAssemblyAnalysis = None,
    pool: ConnectionPool = None,
    file_enriched=None,
):
    """
    Store DotNet analysis results in the database, including creating findings and transforms.

    Args:
        object_id (str): The object ID of the file that was analyzed
        decompilation_object_id (str, optional): Object ID of the decompiled source ZIP
        analysis (DotNetAssemblyAnalysis, optional): Assembly analysis results
        pool (ConnectionPool, optional): Database connection pool
        file_enriched: The FileEnriched object for the original file
    """
    try:
        # Update workflow success status
        try:
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE workflows
                        SET enrichments_success = array_append(enrichments_success, %s)
                        WHERE object_id = %s
                        """,
                        ("dotnet_service", object_id),
                    )
                    conn.commit()
        except Exception as db_error:
            logger.error(f"Failed to update dotnet_service enrichment success in database: {str(db_error)}")

        # Create an enrichment result to store
        enrichment_result = EnrichmentResult(module_name="dotnet_service")
        enrichment_result.results = {}

        # Handle decompilation results
        if decompilation_object_id:
            if not file_enriched:
                logger.warning("file_enriched is None, cannot create decompilation transform")
            else:
                # Create decompilation transform
                decompilation = Transform(
                    type="decompilation",
                    object_id=decompilation_object_id,
                    metadata={
                        "file_name": f"{file_enriched.file_name}.zip",
                        "offer_as_download": True,
                        "display_title": "Decompiled Source Code",
                    },
                )
                enrichment_result.transforms = [decompilation]

                # Publish the decompiled file as a new file message
                file_message = File(
                    object_id=decompilation_object_id,
                    agent_id=file_enriched.agent_id,
                    project=file_enriched.project,
                    timestamp=file_enriched.timestamp,
                    expiration=file_enriched.expiration,
                    path=f"{file_enriched.path}/decompiled.zip",
                    originating_object_id=file_enriched.object_id,
                    nesting_level=(file_enriched.nesting_level or 0) + 1,
                )

                with DaprClient() as dapr_client:
                    data = json.dumps(file_message.model_dump(exclude_unset=True, mode="json"))
                    dapr_client.publish_event(
                        pubsub_name="pubsub",
                        topic_name="file",
                        data=data,
                        data_content_type="application/json",
                    )

                logger.info(
                    "Submitted decompiled source ZIP to Nemesis",
                    decompiled_object_id=decompilation_object_id,
                    originating_object_id=object_id,
                )

        # Handle analysis results
        findings_list = []
        if analysis:
            # Store the analysis results
            enrichment_result.results["inspect_assembly"] = sanitize_for_jsonb(analysis.model_dump())

            # Check if there are any significant findings worth creating a finding for
            has_significant_findings = (
                analysis.IsWCFServer
                or analysis.IsWCFClient
                or analysis.RemotingChannels
                or analysis.SerializationGadgetCalls
                or analysis.WcfServerCalls
                or analysis.ClientCalls
                or analysis.RemotingCalls
                or analysis.ExecutionCalls
            )

            if has_significant_findings:
                # Generate summary for the finding
                summary_markdown = create_dotnet_finding_summary(analysis)

                # Create display data
                display_data = FileObject(
                    type="finding_summary",
                    metadata={"summary": sanitize_for_jsonb(summary_markdown)},
                )

                # Create the finding
                finding = Finding(
                    category=FindingCategory.VULNERABILITY,
                    finding_name="dotnet_vulns",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name="dotnet_service",
                    object_id=object_id,
                    severity=9,
                    raw_data=sanitize_for_jsonb(analysis.model_dump()),
                    data=[display_data],
                )

                findings_list.append(finding)

        # Add findings to enrichment result
        enrichment_result.findings = findings_list

        def store_in_db():
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    # Store main enrichment result
                    results_escaped = json.dumps(sanitize_for_jsonb(enrichment_result.model_dump(mode="json")))
                    cur.execute(
                        """
                        INSERT INTO enrichments (object_id, module_name, result_data)
                        VALUES (%s, %s, %s)
                        """,
                        (object_id, "dotnet_service", results_escaped),
                    )

                    # Store any transforms
                    if enrichment_result.transforms:
                        for transform in enrichment_result.transforms:
                            cur.execute(
                                """
                                INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                                VALUES (%s, %s, %s, %s)
                                """,
                                (
                                    object_id,
                                    transform.type,
                                    transform.object_id,
                                    json.dumps(transform.metadata) if transform.metadata else None,
                                ),
                            )

                    # Store any findings
                    for finding in findings_list:
                        # Convert each FileObject to a JSON string
                        data_as_strings = []
                        for obj in finding.data:
                            # Convert the model to a dict first
                            if hasattr(obj, "model_dump"):
                                obj_dict = obj.model_dump()
                            else:
                                obj_dict = obj
                            sanitized_obj = sanitize_for_jsonb(obj_dict)
                            data_as_strings.append(json.dumps(sanitized_obj))

                        cur.execute(
                            """
                            INSERT INTO findings (
                                finding_name, category, severity, object_id,
                                origin_type, origin_name, raw_data, data
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                finding.finding_name,
                                finding.category,
                                finding.severity,
                                object_id,
                                finding.origin_type,
                                finding.origin_name,
                                json.dumps(sanitize_for_jsonb(finding.raw_data)),
                                json.dumps(data_as_strings),  # Store as array of JSON strings
                            ),
                        )

                conn.commit()

        # Run database operations in thread
        await asyncio.to_thread(store_in_db)

        logger.info("Successfully stored DotNet results", object_id=object_id, has_findings=len(findings_list) > 0)

        return enrichment_result

    except Exception as e:
        logger.exception(e, message="Error storing DotNet results", object_id=object_id)
        return None
