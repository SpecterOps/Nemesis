"""OpenTelemetry tracing for file_enrichment.

With NEMESIS_MONITORING=enabled, spans are exported over OTLP (OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, the
otel-collector) and the app and its clients are instrumented:
- FastAPI: each request from the Dapr sidecar (pub/sub deliveries) continues the sidecar's trace
- gRPC: trace context reaches the sidecar on every call, so scheduling a workflow or publishing from an activity
  joins the caller's trace
- asyncpg, urllib3 (S3) and aiohttp: database, object storage and HTTP calls get spans of their own
Otherwise spans are not recorded at all.
"""

import os
from importlib.metadata import version
from uuid import UUID

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF
from opentelemetry.semconv._incubating.attributes import service_attributes

SERVICE_NAME = "file_enrichment"

_tracer: trace.Tracer | None = None
_instrumented = False


def monitoring_enabled() -> bool:
    return os.getenv("NEMESIS_MONITORING", "").lower() == "enabled"


def get_instance_id() -> str:
    hostname = os.getenv("HOSTNAME", "unknown-host")  # Docker: container ID, K8s: pod name
    return f"{hostname}-{os.getpid()}"


def _create_provider() -> TracerProvider:
    resource = Resource.create(
        {
            service_attributes.SERVICE_NAME: SERVICE_NAME,
            service_attributes.SERVICE_NAMESPACE: "nemesis",
            service_attributes.SERVICE_VERSION: version(SERVICE_NAME),
            service_attributes.SERVICE_INSTANCE_ID: get_instance_id(),
        }
    )
    if not monitoring_enabled():
        # Nothing would be exported, so don't record spans (non-recording spans are nearly free)
        return TracerProvider(resource=resource, sampler=ALWAYS_OFF)

    provider = TracerProvider(resource=resource)
    insecure = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_INSECURE", "true").lower() == "true"
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(insecure=insecure)))
    return provider


def get_tracer() -> trace.Tracer:
    """The service tracer; the first call installs the global tracer provider."""
    global _tracer
    if _tracer is None:
        provider = _create_provider()
        trace.set_tracer_provider(provider)
        _tracer = provider.get_tracer(SERVICE_NAME)
    return _tracer


# Polled endpoints that would only add noise traces
UNTRACED_URLS = "healthz,metrics,system/pool-stats"


def setup_tracing(app: FastAPI) -> None:
    """Install the tracer provider and, with monitoring enabled, instrument the app and client libraries (once).

    Call when the app is created, before the lifespan opens any async gRPC channel (the aio Dapr and workflow
    clients): the gRPC instrumentation only covers channels created after it. Sync gRPC channels are instrumented by
    the Dapr workflow SDK itself when opentelemetry-instrumentation-grpc is installed.
    """
    global _instrumented

    get_tracer()
    if _instrumented or not monitoring_enabled():
        return

    from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
    from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.grpc import GrpcAioInstrumentorClient
    from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor

    FastAPIInstrumentor.instrument_app(app, excluded_urls=UNTRACED_URLS, exclude_spans=["receive", "send"])
    GrpcAioInstrumentorClient().instrument()
    AsyncPGInstrumentor().instrument()
    URLLib3Instrumentor().instrument()  # S3 (minio)
    AioHttpClientInstrumentor().instrument()
    _instrumented = True


def set_object_id_attribute(span: trace.Span, object_id: UUID, key: str = "object_id") -> None:
    """Record an object ID on a span (OpenTelemetry attributes must be primitive types)."""
    span.set_attribute(key, str(object_id))
