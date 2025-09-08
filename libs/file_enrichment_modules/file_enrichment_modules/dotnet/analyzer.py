# enrichment_modules/dotnet_analyzer/analyzer.py
import hashlib
import json
from pathlib import Path
from typing import Union

import dnfile
import structlog
from common.models import (
    DotNetInput,
    EnrichmentResult,
)
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


class DotNetAnalyzer(EnrichmentModule):
    def __init__(self):
        super().__init__("dotnet_analyzer", dependencies=["pe"])
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run."""
        # get the current `file_enriched` from the database backend
        file_enriched = get_file_enriched(object_id)
        should_run = "mono/.net assembly" in file_enriched.magic_type.lower()

        return should_run

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process file using the dotnet service."""
        try:
            # get the current `file_enriched` FileEnriched object from the database backend
            file_enriched = get_file_enriched(object_id)

            # publish a `dotnet-input` message for the process-heavy decompilation and InspectAssembly analysis in `dotnet_service`
            dotnet_input = DotNetInput(object_id=object_id)
            with DaprClient() as client:
                client.publish_event(
                    pubsub_name="pubsub",
                    topic_name="dotnet-input",
                    data=json.dumps(dotnet_input.model_dump()),
                    data_content_type="application/json",
                )

            enrichment = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

            # Get results from local parsing
            if file_path:
                enrichment.results = {"parsed": parse_dotnet_assembly(file_path)}
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    enrichment.results = {"parsed": parse_dotnet_assembly(temp_file.name)}

            return enrichment

        except Exception as e:
            logger.exception(e, message="Error processing file", file_object_id=object_id)


def create_enrichment_module() -> EnrichmentModule:
    return DotNetAnalyzer()
