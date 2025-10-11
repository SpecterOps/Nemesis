# import os
# from importlib.metadata import version

# from opentelemetry import trace
# from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
# from opentelemetry.sdk.resources import Resource
# from opentelemetry.sdk.trace import TracerProvider
# from opentelemetry.sdk.trace.export import BatchSpanProcessor
# from opentelemetry.semconv.resource import ResourceAttributes

from typing import Any, Optional
from contextlib import contextmanager


class NoOpSpan:
    """No-op span for when tracing is disabled."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_attributes(self, attributes: dict) -> None:
        pass

    def add_event(self, name: str, attributes: Optional[dict] = None) -> None:
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


# def get_instance_id():
#     hostname = os.getenv("HOSTNAME", "unknown-host")  # Docker: container ID, K8s: pod name
#     pid = os.getpid()  # Uvicorn/Gunicorn worker PID
#     return f"{hostname}-{pid}"


def get_tracer(tracer_name: str, otel_exporter_enabled: bool = True):
    """Return a no-op tracer (OpenTelemetry temporarily disabled to avoid dependency conflicts)."""
    return NoOpTracer()

    # """Initialize and return an OpenTelemetry tracer with the specified name."""
    #
    # # Check if tracer provider is already set
    # current_provider = trace.get_tracer_provider()
    # if hasattr(current_provider, "_resource") or type(current_provider).__name__ != "NoOpTracerProvider":
    #     # Tracer provider already configured, just return the tracer
    #     return current_provider.get_tracer(tracer_name)
    #
    # resource = Resource.create(
    #     {
    #         ResourceAttributes.SERVICE_NAME: "file-enrichment-controller",
    #         ResourceAttributes.SERVICE_NAMESPACE: "nemesis",
    #         ResourceAttributes.SERVICE_VERSION: version("file_enrichment"),
    #         ResourceAttributes.SERVICE_INSTANCE_ID: get_instance_id(),
    #     }
    # )
    #
    # # Only setup OTLP exporter if monitoring is enabled
    # if os.getenv("NEMESIS_MONITORING", "").lower() == "enabled":
    #     otlp_exporter = OTLPSpanExporter(
    #         insecure=os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_INSECURE", "true").lower() == "true",
    #     )
    #
    #     trace_provider = TracerProvider(resource=resource)
    #     span_processor = BatchSpanProcessor(otlp_exporter)
    #     trace_provider.add_span_processor(span_processor)
    #     trace.set_tracer_provider(trace_provider)
    # else:
    #     trace_provider = TracerProvider(resource=resource)
    #     trace.set_tracer_provider(trace_provider)
    #
    # return trace_provider.get_tracer(tracer_name)
