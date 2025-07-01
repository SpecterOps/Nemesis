import logging
import os
from importlib.metadata import version

import colorlog
import structlog
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.semconv.resource import ResourceAttributes


# Create a processor to add worker ID
def add_worker_id(logger, method_name, event_dict):
    try:
        import multiprocessing

        event_dict["worker_id"] = multiprocessing.current_process().name
    except (ImportError, AttributeError):
        event_dict["worker_id"] = "unknown"
    return event_dict


def configure_logging():
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    # Validate the log level
    numeric_level = getattr(logging, log_level, None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    # Set up colorlog handler
    handler = colorlog.StreamHandler()

    # Create a ProcessorFormatter for structlog that includes color formatting
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer(colors=True),
        foreign_pre_chain=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
        ],
    )

    # Set the formatter once
    handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    # root_logger.setLevel(logging.DEBUG)
    root_logger.setLevel(numeric_level)

    # Clear any existing handlers to prevent double logging
    root_logger.handlers = []
    root_logger.addHandler(handler)

    # Configure specific loggers
    logging.getLogger("plyara.core").setLevel(logging.WARN)
    logging.getLogger("WorkflowRuntime").setLevel(logging.WARN)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARN)
    logging.getLogger("asyncio").setLevel(logging.WARN)
    logging.getLogger("opentelemetry.sdk.trace").setLevel(logging.ERROR)

    DaprWorkflowContext_logger = logging.getLogger("DaprWorkflowContext")
    DaprWorkflowContext_logger.setLevel(logging.WARN)
    DaprWorkflowContext_logger.handlers = []
    DaprWorkflowContext_logger.addHandler(handler)
    DaprWorkflowContext_logger.propagate = False

    # Configure structlog to use the same handler
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            # add_worker_id,
            structlog.stdlib.add_log_level,
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    return handler, formatter


def get_instance_id():
    hostname = os.getenv("HOSTNAME", "unknown-host")  # Docker: container ID, K8s: pod name
    pid = os.getpid()  # Uvicorn/Gunicorn worker PID
    return f"{hostname}-{pid}"


def get_tracer(tracer_name: str, otel_exporter_enabled: bool = True):
    """Initialize and return an OpenTelemetry tracer with the specified name."""

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
