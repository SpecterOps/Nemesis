"""OpenTelemetry tracing for Nemesis services.

Call setup_tracing(app, "<service>") once when the FastAPI app is created. With NEMESIS_MONITORING=enabled, spans
are exported over OTLP to OTEL_EXPORTER_OTLP_TRACES_ENDPOINT (default: the otel-collector service) and the app and
its clients are instrumented:
- FastAPI: each request continues the caller's trace (e.g. the Dapr sidecar's pub/sub delivery span)
- gRPC: trace context reaches the Dapr sidecar on every call, so scheduling a workflow or publishing an event joins
  the caller's trace
- asyncpg, psycopg, urllib3 (S3), aiohttp and httpx: database, object storage and HTTP calls get spans of their own
Otherwise spans are not recorded at all.
"""

import os
from importlib.metadata import PackageNotFoundError, version
from uuid import UUID

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF
from opentelemetry.semconv._incubating.attributes import service_attributes

DEFAULT_OTLP_ENDPOINT = "http://otel-collector:4317"  # the collector's name in docker compose and in the Helm chart

# Polled endpoints that would only add noise traces
UNTRACED_URLS = "healthz,metrics,system/pool-stats"

_tracer: trace.Tracer | None = None
_instrumented = False


def monitoring_enabled() -> bool:
    return os.getenv("NEMESIS_MONITORING", "").lower() == "enabled"


def get_instance_id() -> str:
    hostname = os.getenv("HOSTNAME", "unknown-host")  # Docker: container ID, K8s: pod name
    return f"{hostname}-{os.getpid()}"


def _service_version(service_name: str) -> str:
    try:
        return version(service_name)
    except PackageNotFoundError:
        return "unknown"


def _create_provider(service_name: str) -> TracerProvider:
    resource = Resource.create(
        {
            service_attributes.SERVICE_NAME: service_name,
            service_attributes.SERVICE_NAMESPACE: "nemesis",
            service_attributes.SERVICE_VERSION: _service_version(service_name),
            service_attributes.SERVICE_INSTANCE_ID: get_instance_id(),
        }
    )
    if not monitoring_enabled():
        # Nothing would be exported, so don't record spans (non-recording spans are nearly free)
        return TracerProvider(resource=resource, sampler=ALWAYS_OFF)

    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", DEFAULT_OTLP_ENDPOINT),
        insecure=os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_INSECURE", "true").lower() == "true",
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    return provider


def get_tracer() -> trace.Tracer:
    """The service tracer (non-recording until setup_tracing has run)."""
    return _tracer or trace.get_tracer("nemesis")


def setup_tracing(app: FastAPI, service_name: str) -> None:
    """Install the tracer provider and, with monitoring enabled, instrument the app and client libraries (once).

    Call when the app is created: before any gRPC channel is opened (Dapr and workflow clients), since the gRPC
    instrumentation only covers channels created after it.
    """
    global _tracer, _instrumented

    if _tracer is None:
        provider = _create_provider(service_name)
        trace.set_tracer_provider(provider)
        _tracer = provider.get_tracer(service_name)
    if _instrumented or not monitoring_enabled():
        return

    from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
    from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.grpc import GrpcAioInstrumentorClient, GrpcInstrumentorClient
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
    from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor

    FastAPIInstrumentor.instrument_app(app, excluded_urls=UNTRACED_URLS, exclude_spans=["receive", "send"])
    for instrumentor in (
        GrpcInstrumentorClient(),
        GrpcAioInstrumentorClient(),
        AsyncPGInstrumentor(),
        PsycopgInstrumentor(),
        URLLib3Instrumentor(),  # S3 (minio)
        AioHttpClientInstrumentor(),
        HTTPXClientInstrumentor(),
    ):
        if not instrumentor.is_instrumented_by_opentelemetry:  # the Dapr workflow SDK instruments sync gRPC itself
            instrumentor.instrument()
    _instrumented = True


def set_object_id_attribute(span: trace.Span, object_id: UUID, key: str = "object_id") -> None:
    """Record an object ID on a span (OpenTelemetry attributes must be primitive types)."""
    span.set_attribute(key, str(object_id))
