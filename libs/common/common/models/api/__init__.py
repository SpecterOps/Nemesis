"""API models - all models used in HTTP API routes."""

from .chatbot import ChatbotMessage, ChatbotRequest, CleanupRequest
from .common import (
    APIInfo,
    ErrorResponse,
    HealthResponse,
    UTCDatetime,
    YaraReloadResponse,
)
from .containers import ContainerStatusResponse, ContainerSubmissionResponse

# DPAPI models require nemesis_dpapi package - import conditionally
try:
    from .dpapi import (  # noqa: F401
        ChromiumAppBoundKeyCredential,
        DomainBackupKeyCredential,
        DpapiCredentialRequest,
        DpapiSystemCredentialRequest,
        MasterKeyGuidPair,
        MasterKeyGuidPairList,
        NtlmHashCredentialKey,
        PasswordCredentialKey,
        Pbkdf2StrongCredentialKey,
        Sha1CredentialKey,
    )

    _DPAPI_AVAILABLE = True
except ImportError:
    _DPAPI_AVAILABLE = False

from .enrichments import (
    BulkEnrichmentResponse,
    BulkEnrichmentStatusResponse,
    BulkEnrichmentStopResponse,
    EnrichmentRequest,
    EnrichmentResponse,
    EnrichmentsListResponse,
    ModulesListResponse,
)
from .files import (
    ContainerFromMountRequest,
    FileFilters,
    FileMetadata,
    FileWithMetadataResponse,
)
from .queues import QueueMetrics, QueuesResponse, QueueSummary, SingleQueueResponse
from .reports import (
    LLMSynthesisResponse,
    RiskIndicators,
    SourceReport,
    SourceSummary,
    SystemReport,
    TimelineEntry,
    TopFinding,
)
from .workflows import (
    ActiveWorkflowDetail,
    FailedWorkflowsResponse,
    WorkflowMetrics,
    WorkflowProcessingStats,
    WorkflowStatusResponse,
)

__all__ = [
    # common
    "ErrorResponse",
    "HealthResponse",
    "YaraReloadResponse",
    "APIInfo",
    "UTCDatetime",
    # files
    "FileFilters",
    "FileMetadata",
    "FileWithMetadataResponse",
    "ContainerFromMountRequest",
    # enrichments
    "EnrichmentRequest",
    "EnrichmentResponse",
    "ModulesListResponse",
    "EnrichmentsListResponse",
    "BulkEnrichmentResponse",
    "BulkEnrichmentStatusResponse",
    "BulkEnrichmentStopResponse",
    # workflows
    "WorkflowProcessingStats",
    "WorkflowMetrics",
    "ActiveWorkflowDetail",
    "WorkflowStatusResponse",
    "FailedWorkflowsResponse",
    # containers
    "ContainerSubmissionResponse",
    "ContainerStatusResponse",
    # queues
    "QueueMetrics",
    "QueueSummary",
    "QueuesResponse",
    "SingleQueueResponse",
    # reports
    "SourceSummary",
    "RiskIndicators",
    "TimelineEntry",
    "TopFinding",
    "SourceReport",
    "SystemReport",
    "LLMSynthesisResponse",
    # chatbot
    "ChatbotMessage",
    "ChatbotRequest",
    "CleanupRequest",
]

# Add dpapi models to __all__ if available
if _DPAPI_AVAILABLE:
    __all__.extend(
        [
            "PasswordCredentialKey",
            "NtlmHashCredentialKey",
            "Sha1CredentialKey",
            "Pbkdf2StrongCredentialKey",
            "DomainBackupKeyCredential",
            "MasterKeyGuidPair",
            "MasterKeyGuidPairList",
            "DpapiSystemCredentialRequest",
            "ChromiumAppBoundKeyCredential",
            "DpapiCredentialRequest",
        ]
    )
