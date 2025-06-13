import logging
import os

import colorlog
import structlog


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
