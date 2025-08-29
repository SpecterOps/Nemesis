import logging
import os
import sys

import structlog
from structlog.stdlib import ProcessorFormatter

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
NUMERIC_LEVEL = getattr(logging, LOG_LEVEL, logging.INFO)

WORKFLOW_RUNTIME_LOG_LEVEL = os.getenv("WORKFLOW_RUNTIME_LOG_LEVEL", "WARNING")
WORKFLOW_CLIENT_LOG_LEVEL = os.getenv("WORKFLOW_CLIENT_LOG_LEVEL", "WARNING")


def add_worker_id(logger, method_name, event_dict):
    try:
        import multiprocessing

        event_dict["worker_id"] = multiprocessing.current_process().name
    except (ImportError, AttributeError):
        event_dict["worker_id"] = "unknown"
    return event_dict


def add_callsite_from_record(_logger, _method, event_dict):
    record = event_dict.get("_record")
    if record is not None:
        event_dict.setdefault("logger", record.name)
        event_dict.setdefault("module", record.module)
        event_dict.setdefault("func", record.funcName)
        event_dict.setdefault("line", record.lineno)
    return event_dict


foreign_pre_chain = [
    add_callsite_from_record,
    add_worker_id,
    structlog.stdlib.add_log_level,
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
]

formatter = ProcessorFormatter(
    processor=structlog.dev.ConsoleRenderer(colors=True),
    foreign_pre_chain=foreign_pre_chain,
)

handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)

root = logging.getLogger()
root.handlers[:] = [handler]
root.setLevel("WARNING")
logging.captureWarnings(True)

# structlog -> hand off to ProcessorFormatter (no direct rendering here)
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,  # adds "logger" for your own logs
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        ProcessorFormatter.wrap_for_formatter,  # defer final render
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)


def get_logger(name=None):
    logging.getLogger(name).setLevel(LOG_LEVEL)
    return structlog.get_logger(name)
