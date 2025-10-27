import os
from importlib.metadata import version

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.semconv._incubating.attributes import service_attributes
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# Module-level tracer singleton
_tracer = None


def get_instance_id():
    hostname = os.getenv("HOSTNAME", "unknown-host")  # Docker: container ID, K8s: pod name
    pid = os.getpid()  # Uvicorn/Gunicorn worker PID
    return f"{hostname}-{pid}"


def get_trace_injector():
    """
    Returns a callback that injects W3C trace context into Dapr headers.

    This enables distributed tracing across Dapr service boundaries by propagating
    traceparent and tracestate headers per W3C Trace Context specification.

    The returned callback should be passed to DaprClient's headers_callback parameter
    to automatically include trace context in all Dapr operations (pub/sub, service
    invocation, state operations, etc.).

    Returns:
        Callable that returns dict of trace headers with current trace context

    Example:
        >>> from dapr.clients import DaprClient
        >>> with DaprClient(headers_callback=get_trace_injector()) as client:
        ...     client.publish_event(
        ...         pubsub_name="pubsub",
        ...         topic_name="my-topic",
        ...         data=json.dumps({"key": "value"})
        ...     )

    Note:
        This function must be called within an active OpenTelemetry span context
        for trace propagation to work. If called outside a span, it returns empty
        headers which is safe but provides no trace context.
    """

    def inject_trace_context():
        headers = {}
        TraceContextTextMapPropagator().inject(carrier=headers)
        return headers

    return inject_trace_context


def get_tracer(module_name: str = "file_enrichment"):
    """
    Initialize and return an OpenTelemetry tracer for the file_enrichment service.

    This function uses a module-level singleton pattern to ensure the tracer is
    initialized only once. Subsequent calls return the same tracer instance.

    Tracing behavior is controlled by the NEMESIS_MONITORING environment variable:
    - When enabled: Spans are exported to an OTLP endpoint (e.g., Jaeger)
    - When disabled: Spans are created but not exported (in-memory only)

    Args:
        module_name: The module name used to identify the tracer and determine
                    the service version from package metadata (default: "file_enrichment")

    Returns:
        A configured OpenTelemetry Tracer instance that can be used to create spans.

    Environment Variables:
        NEMESIS_MONITORING: Set to "enabled" to export traces to OTLP endpoint
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_INSECURE: Set to "true" for insecure
                                                      connections (default: "true")
        HOSTNAME: Used to construct the service instance ID

    Example:
        >>> tracer = get_tracer()
        >>> with tracer.start_as_current_span("my_operation") as span:
        ...     span.set_attribute("key", "value")
        ...     # ... do work ...
    """
    global _tracer

    # Return existing tracer if already initialized
    if _tracer is not None:
        return _tracer

    # Create resource with service metadata
    resource = Resource.create(
        {
            service_attributes.SERVICE_NAME: "file_enrichment",
            service_attributes.SERVICE_NAMESPACE: "nemesis",
            service_attributes.SERVICE_VERSION: version(module_name),
            service_attributes.SERVICE_INSTANCE_ID: get_instance_id(),
        }
    )

    # Create TracerProvider and configure export based on monitoring setting
    trace_provider = TracerProvider(resource=resource)

    # Only setup OTLP exporter if monitoring is enabled
    monitoring_enabled = os.getenv("NEMESIS_MONITORING", "").lower() == "enabled"
    if monitoring_enabled:
        otlp_exporter = OTLPSpanExporter(
            insecure=os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_INSECURE", "true").lower() == "true",
        )
        span_processor = BatchSpanProcessor(otlp_exporter)
        trace_provider.add_span_processor(span_processor)

    # Set as global tracer provider
    trace.set_tracer_provider(trace_provider)

    # Cache and return tracer
    _tracer = trace_provider.get_tracer(module_name)
    return _tracer
