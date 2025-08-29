import logging
import os
from importlib.metadata import version

import colorlog
import structlog
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as HTTPOTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
from opentelemetry.semconv.resource import ResourceAttributes

WORKFLOW_RUNTIME_LOG_LEVEL = os.getenv("WORKFLOW_RUNTIME_LOG_LEVEL", "WARNING")
WORKFLOW_CLIENT_LOG_LEVEL = os.getenv("WORKFLOW_CLIENT_LOG_LEVEL", "WARNING")


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
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARN)
    logging.getLogger("asyncio").setLevel(logging.WARN)
    logging.getLogger("opentelemetry.sdk.trace").setLevel(logging.ERROR)
    logging.getLogger("httpx").setLevel(logging.WARN)
    logging.getLogger("httpcore").setLevel(logging.WARN)
    logging.getLogger("httpcore.connection").setLevel(logging.WARN)
    logging.getLogger("httpcore.http11").setLevel(logging.WARN)
    logging.getLogger("openai").setLevel(logging.WARN)
    logging.getLogger("openai._base_client").setLevel(logging.WARN)
    logging.getLogger("anthropic").setLevel(logging.WARN)
    logging.getLogger("websockets").setLevel(logging.WARN)
    logging.getLogger("websockets.client").setLevel(logging.WARN)
    logging.getLogger("gql").setLevel(logging.WARN)
    logging.getLogger("gql.transport").setLevel(logging.WARN)
    logging.getLogger("gql.transport.websockets").setLevel(logging.WARN)
    logging.getLogger("gql.dsl").setLevel(logging.WARN)

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
            ResourceAttributes.SERVICE_NAME: "agents",
            ResourceAttributes.SERVICE_NAMESPACE: "nemesis",
            ResourceAttributes.SERVICE_VERSION: version("agents"),
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


# Global storage for agent metadata
_agent_metadata = {}


def set_agent_metadata(agent_name: str, **kwargs):
    """Set metadata that will be added to the next agent span"""
    global _agent_metadata
    _agent_metadata = {"agent_name": agent_name, **kwargs}


def setup_phoenix_llm_tracing():
    """
    Setup Phoenix tracing ONLY for LLM calls - adds Phoenix exporter to existing tracer.
    """
    if os.getenv("PHOENIX_ENABLED", "false").lower() == "true":
        logger = structlog.get_logger(__name__)
        logger.info("Phoenix enabled, setting up LLM tracing")

        try:
            # Import Phoenix/OpenInference components
            import json

            from openinference.instrumentation.pydantic_ai import OpenInferenceSpanProcessor, is_openinference_span
            from openinference.semconv.trace import SpanAttributes
            from opentelemetry.sdk.trace import Span

            # Custom processor that enhances Pydantic AI spans with our metadata
            class CustomPydanticAIProcessor(OpenInferenceSpanProcessor):
                def on_start(self, span: Span, parent_context=None):
                    """Modify span when it starts"""
                    super().on_start(span, parent_context)

                    # Check if this is a Pydantic AI span
                    if hasattr(span, "name") and "agent" in span.name.lower():
                        global _agent_metadata
                        if _agent_metadata:
                            # Update span name if agent_name provided
                            if "agent_name" in _agent_metadata:
                                span.update_name(_agent_metadata["agent_name"])
                                # Also set the AGENT_NAME attribute using OpenInference convention
                                span.set_attribute(SpanAttributes.AGENT_NAME, _agent_metadata["agent_name"])

                            # Set session ID if file_path is provided (use file path as session)
                            if "file_path" in _agent_metadata:
                                span.set_attribute(SpanAttributes.SESSION_ID, _agent_metadata["file_path"])

                            # Add other metadata using METADATA attribute (OpenInference convention)
                            metadata = {
                                k: v for k, v in _agent_metadata.items() if k not in ["agent_name"] and v is not None
                            }
                            if metadata:
                                span.set_attribute(SpanAttributes.METADATA, json.dumps(metadata))

                            # Add tags if provided
                            if "tags" in _agent_metadata and isinstance(_agent_metadata["tags"], list):
                                span.set_attribute(SpanAttributes.TAG_TAGS, _agent_metadata["tags"])

            # Get the existing tracer provider (already set up for Jaeger)
            existing_provider = trace.get_tracer_provider()

            if not isinstance(existing_provider, TracerProvider):
                logger.warning("No existing TracerProvider found, Phoenix tracing not enabled")
                return False

            # Phoenix exporter using HTTP OTLP
            phoenix_endpoint = os.getenv("PHOENIX_ENDPOINT", "http://phoenix:6006/v1/traces")
            phoenix_exporter = HTTPOTLPSpanExporter(endpoint=phoenix_endpoint)

            # Add our custom processor to enhance spans
            existing_provider.add_span_processor(CustomPydanticAIProcessor(span_filter=is_openinference_span))

            # Create a filtering processor that ONLY sends Pydantic AI spans to Phoenix
            class PhoenixLLMOnlyProcessor(SimpleSpanProcessor):
                """Only send Pydantic AI LLM spans to Phoenix, not healthchecks"""

                def on_end(self, span):
                    # Only export if this is a Pydantic AI span (has OpenInference attributes)
                    if is_openinference_span(span):
                        super().on_end(span)

            # Add Phoenix exporter with strict LLM-only filtering
            existing_provider.add_span_processor(PhoenixLLMOnlyProcessor(phoenix_exporter))

            logger.info("Phoenix LLM tracing with custom processor added", endpoint=phoenix_endpoint)

            logger.info("Phoenix LLM tracing successfully initialized")
            return True

        except ImportError as e:
            logger.error(f"Failed to import Phoenix instrumentation: {e}")
            logger.error("Make sure openinference-instrumentation-pydantic-ai is installed")
            return False
        except Exception as e:
            logger.exception("Failed to setup Phoenix tracing", error=str(e))
            return False

    else:
        logger.debug("Phoenix tracing disabled (PHOENIX_ENABLED not set to 'true')")
        return False
