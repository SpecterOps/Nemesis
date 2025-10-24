import os
from contextlib import contextmanager
from importlib.metadata import version
from typing import Any

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.semconv._incubating.attributes import service_attributes


class NoOpSpan:
    """No-op span for when tracing is disabled."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_attributes(self, attributes: dict) -> None:
        pass

    def add_event(self, name: str, attributes: dict | None = None) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class NoOpTracer:
    """No-op tracer for when tracing is disabled."""

    @contextmanager
    def start_as_current_span(self, name: str, **kwargs):
        yield NoOpSpan()

    def start_span(self, name: str, **kwargs):
        return NoOpSpan()


def get_instance_id():
    hostname = os.getenv("HOSTNAME", "unknown-host")  # Docker: container ID, K8s: pod name
    pid = os.getpid()  # Uvicorn/Gunicorn worker PID
    return f"{hostname}-{pid}"


def get_tracer(module: str, service: str, otel_exporter_enabled: bool = True):
    """
    Initialize and return an OpenTelemetry tracer with the specified module and service name.

    This function creates or reuses a TracerProvider with service metadata and configures
    trace export based on the NEMESIS_MONITORING environment variable. When monitoring
    is enabled, spans are exported to an OTLP endpoint (e.g., Jaeger). Otherwise,
    tracing is still active but spans are not exported.

    If a TracerProvider is already configured, this function reuses it rather than
    creating a new one, allowing multiple modules to share the same tracing configuration.

    Args:
        module: The module name used to identify this tracer instance and determine
                the service version from package metadata.
        service: The service name to identify this service in the tracing backend.
        otel_exporter_enabled: Currently unused parameter. Export behavior is
                             controlled by the NEMESIS_MONITORING env var instead.

    Returns:
        A configured OpenTelemetry Tracer instance that can be used to create spans.

    Environment Variables:
        NEMESIS_MONITORING: Set to "enabled" to export traces to OTLP endpoint
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_INSECURE: Set to "true" for insecure
                                                      connections (default: "true")
        HOSTNAME: Used to construct the service instance ID

    Note:
        There is a commented-out line that previously returned a NoOpTracer when
        OpenTelemetry was disabled to avoid dependency conflicts. This is no longer used.
    """

    # Check if tracer provider is already set
    current_provider = trace.get_tracer_provider()
    if hasattr(current_provider, "_resource") or type(current_provider).__name__ != "NoOpTracerProvider":
        # Tracer provider already configured, just return the tracer
        return current_provider.get_tracer(module)

    resource = Resource.create(
        {
            service_attributes.SERVICE_NAME: service,
            service_attributes.SERVICE_NAMESPACE: "nemesis",
            service_attributes.SERVICE_VERSION: version(module),
            service_attributes.SERVICE_INSTANCE_ID: get_instance_id(),
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

    return trace_provider.get_tracer(module)
