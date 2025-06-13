# enrichment_modules/dotnet_analyzer/analyzer.py
import hashlib
import json
from pathlib import Path
from typing import Union

import dnfile
import structlog
from common.models import EnrichmentResult, File, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.clients import DaprClient

from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


def get_typerefs(assembly):
    """Extract TypeRef information from .NET assembly."""
    tr = assembly.net.mdtables.TypeRef
    if not tr or tr.num_rows < 1 or not tr.rows:
        return {}

    typerefs = {}
    for row in tr:
        if row.TypeNamespace.value in typerefs:
            typerefs[row.TypeNamespace.value].append(row.TypeName.value)
        else:
            typerefs[row.TypeNamespace.value] = [row.TypeName.value]

    return typerefs


def process_resources(assembly):
    """Process and hash .NET assembly resources."""
    resources = {}

    for r in assembly.net.resources:
        if isinstance(r.data, bytes):
            resources[str(r.name)] = {
                "md5": hashlib.md5(r.data).hexdigest(),
                "sha1": hashlib.sha1(r.data).hexdigest(),
                "sha256": hashlib.sha256(r.data).hexdigest(),
            }
        elif isinstance(r.data, dnfile.resource.ResourceSet):
            if not r.data.entries:
                continue
            for entry in r.data.entries:
                if entry.data:
                    resources[str(r.name)] = {
                        "md5": hashlib.md5(entry.data).hexdigest(),
                        "sha1": hashlib.sha1(entry.data).hexdigest(),
                        "sha256": hashlib.sha256(entry.data).hexdigest(),
                    }

    return resources


def parse_dotnet_assembly(filename: Union[str, Path]) -> dict:
    """
    Parses a .NET assembly file and returns a dictionary of .NET specific data.
    """
    result = {
        "dotnet_version": None,
        "impl_map_entries": [],
        "resources": {},
        "typerefs": {},
    }

    try:
        assembly = dnfile.dnPE(str(filename))

        if assembly.net:
            # .NET version
            if assembly.net.metadata and assembly.net.metadata.struct:
                result["dotnet_version"] = str(assembly.net.metadata.struct.Version)

            # P/Invoke type signatures
            try:
                if assembly.net.mdtables.ImplMap:
                    for row in assembly.net.mdtables.ImplMap:
                        entry = {
                            "module_name": str(row.ImportScope.row.Name) if row.ImportScope.row else None,
                            "function_name": str(row.ImportName),
                        }
                        result["impl_map_entries"].append(entry)
            except Exception:
                logger.exception("Exception parsing impl entries")

            # Resources
            try:
                result["resources"] = process_resources(assembly)
            except Exception as e:
                logger.exception(f"Exception parsing resources: {e}")

            # TypeRefs
            try:
                result["typerefs"] = get_typerefs(assembly)
            except Exception as e:
                logger.exception(f"Exception parsing typerefs: {e}")

    except Exception as e:
        logger.exception(f"Error parsing .NET assembly file: {e}")
        return result

    return result


def dict_to_markdown(data):
    """Generates a markdown report from inspect_assembly data."""
    report = []

    for section, content in data.items():
        if content and content != {} and content != []:
            report.append(f"# {section}")

            if isinstance(content, dict):
                for key, items in content.items():
                    report.append(f"\n### {key}")
                    for item in items:
                        method = item.get("MethodName", "Unknown - Error obtaining method")
                        report.append(f"- Location in Assembly: `{method}`")

                        for key, value in item.items():
                            if key == "MethodName" or not value:
                                continue
                            report.append(f"- {key}: {value}")

            elif isinstance(content, list):
                for item in content:
                    report.append(f"- {item}")

    return "\n".join(report)


def get_non_null_sections(data):
    return {k: v for k, v in data.items() if v and v != {} and v != []}


class DotNetAnalyzer(EnrichmentModule):
    def __init__(self):
        super().__init__("dotnet_analyzer", dependencies=["pe"])
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    def should_process(self, object_id: str) -> bool:
        """Determine if this module should run."""
        # get the current `file_enriched` from the database backend
        file_enriched = get_file_enriched(object_id)
        should_run = "mono/.net assembly" in file_enriched.magic_type.lower()
        logger.debug(f"DotNetAnalyzer should_run: {should_run}")
        return should_run

    def process(self, object_id: str) -> EnrichmentResult | None:
        """Process file using the dotnet service."""
        try:
            # get the current `file_enriched` FileEnriched object from the database backend
            file_enriched = get_file_enriched(object_id)

            enrichment = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

            # Step 1 - Get results from local parsing
            with self.storage.download(file_enriched.object_id) as temp_file:
                enrichment.results = {"parsed": parse_dotnet_assembly(temp_file.name)}

            # Step 2 - call the DotNet API using Dapr SDK
            with DaprClient() as dapr_client:
                response = dapr_client.invoke_method(
                    app_id="dotnet-api",
                    method_name=f"file/{file_enriched.object_id}",
                    http_verb="get",
                    timeout=180,
                )
            service_results = json.loads(response.data)

            # Step 3 - handle any decompilation results
            if (
                "decompilation" in service_results
                and "object_id" in service_results["decompilation"]
                and service_results["decompilation"]["object_id"]
            ):
                decompiled_object_id = service_results["decompilation"]["object_id"]

                # enrichment_result
                decompilation = Transform(
                    type="decompilation",
                    object_id=service_results["decompilation"]["object_id"],
                    metadata={
                        "file_name": f"{file_enriched.file_name}.zip",
                        "offer_as_download": True,
                        "display_title": "Decompiled Source Code",
                    },
                )
                enrichment.transforms = [decompilation]

                file_message = File(
                    object_id=decompiled_object_id,
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
                    f"Submitted decompiled source ZIP to Nemesis",
                    decompiled_object_id=decompiled_object_id,
                    originating_object_id=file_enriched.object_id,
                )

            # Step 5 - handle any deserialization results
            if "inspect_assembly" in service_results and service_results["inspect_assembly"]:
                logger.debug(f"service_results['inspect_assembly']: {service_results['inspect_assembly']}")
                inspect_assembly = get_non_null_sections(service_results["inspect_assembly"])
                if inspect_assembly:
                    # Store the raw enrichment result
                    enrichment.results["inspect_assembly"] = inspect_assembly

                    # Generate a markdown finding summary
                    summary_markdown = dict_to_markdown(inspect_assembly)
                    display_data = FileObject(
                        type="finding_summary",
                        metadata={"summary": summary_markdown},
                    )

                    finding = Finding(
                        category=FindingCategory.VULNERABILITY,
                        finding_name="dotnet_vulns",
                        origin_type=FindingOrigin.ENRICHMENT_MODULE,
                        origin_name=self.name,
                        object_id=file_enriched.object_id,
                        severity=9,
                        raw_data=inspect_assembly,
                        data=[display_data],
                    )

                    enrichment.findings = [finding]

            return enrichment

        except Exception as e:
            logger.exception(e, message="Error processing file", file_object_id=object_id)


def create_enrichment_module() -> EnrichmentModule:
    return DotNetAnalyzer()
