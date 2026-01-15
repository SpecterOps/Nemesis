"""Common models package.

This module re-exports all models for backwards compatibility.
Import models directly: `from common.models import File, Finding, ...`

For API-specific models, use: `from common.models.api import FileMetadata, ...`
"""

# Expose the api submodule
from . import api
from .alerts import Alert
from .core import File, FileEnriched, FileHashes
from .enrichment import (
    BulkEnrichmentEvent,
    EnrichmentResult,
    SingleEnrichmentWorkflowInput,
    Transform,
)
from .findings import FileObject, Finding, FindingCategory, FindingOrigin
from .workflows import (
    CloudEvent,
    DotNetAssemblyAnalysis,
    DotNetInput,
    DotNetMethodInfo,
    DotNetOutput,
    GitCommitInfo,
    MatchInfo,
    MatchLocation,
    NoseyParkerInput,
    NoseyParkerOutput,
    ScanResults,
    ScanStats,
    WorkflowResponse,
    WorkflowStatus,
)

__all__ = [
    # Core models
    "File",
    "FileEnriched",
    "FileHashes",
    # Finding models
    "FileObject",
    "FindingCategory",
    "FindingOrigin",
    "Finding",
    # Enrichment models
    "Transform",
    "EnrichmentResult",
    "BulkEnrichmentEvent",
    "SingleEnrichmentWorkflowInput",
    # DotNet models
    "DotNetInput",
    "DotNetMethodInfo",
    "DotNetAssemblyAnalysis",
    "DotNetOutput",
    # NoseyParker models
    "GitCommitInfo",
    "MatchLocation",
    "MatchInfo",
    "ScanStats",
    "ScanResults",
    "NoseyParkerInput",
    "NoseyParkerOutput",
    # Dapr helpers
    "WorkflowResponse",
    "WorkflowStatus",
    "CloudEvent",
    # Alert model
    "Alert",
    # API submodule
    "api",
]
