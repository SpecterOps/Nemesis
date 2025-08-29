import os
from importlib.metadata import version

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.semconv.resource import ResourceAttributes


def get_instance_id():
    hostname = os.getenv("HOSTNAME", "unknown-host")  # Docker: container ID, K8s: pod name
    pid = os.getpid()  # Uvicorn/Gunicorn worker PID
    return f"{hostname}-{pid}"


def get_tracer(tracer_name: str, otel_exporter_enabled: bool = True):
    """Initialize and return an OpenTelemetry tracer with the specified name."""

    # Check if tracer provider is already set
    current_provider = trace.get_tracer_provider()
    if hasattr(current_provider, "_resource") or type(current_provider).__name__ != "NoOpTracerProvider":
        # Tracer provider already configured, just return the tracer
        return current_provider.get_tracer(tracer_name)

    resource = Resource.create(
        {
            ResourceAttributes.SERVICE_NAME: "file-enrichment-controller",
            ResourceAttributes.SERVICE_NAMESPACE: "nemesis",
            ResourceAttributes.SERVICE_VERSION: version("file_enrichment"),
            ResourceAttributes.SERVICE_INSTANCE_ID: get_instance_id(),
        }
    )

    # Only setup OTLP exporter if monitoring is enabled
    if os.getenv("NEMESIS_MONITORING", "").lower() == "enabled":
        otlp_exporter = OTLPSpanExporter(
            insecure=os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_INSECURE", "true").lower() == "true",
        )

        trace_provider = TracerProvider(resource=resource)
        span_processor = BatchSpanProcessor(otlp_exporter)
        trace_provider.add_span_processor(span_processor)
        trace.set_tracer_provider(trace_provider)
    else:
        trace_provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(trace_provider)

    return trace_provider.get_tracer(tracer_name)
