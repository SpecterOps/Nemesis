# Standard Libraries
import logging

# 3rd Party Libraries
import structlog
from rich.console import Console
from rich.traceback import Traceback


# TODO: Figure out how to use structlog with uvicorn's logging
def configure_logger(enable_json_logs: bool = False, log_level: str = "INFO", environment: str = "development"):
    level: int = logging.getLevelName(log_level)

    if environment == "production":
        configure_prod_logger(level)
    else:
        configure_dev_logger(level)


def rich_traceback(sio, exc_info) -> None:
    """
    Pretty-print *exc_info* to *sio* using the *Rich* package.

    To be passed into `ConsoleRenderer`'s ``exception_formatter`` argument.

    Used by default if *Rich* is installed.

    .. versionadded:: 21.2
    """
    sio.write("\n")
    Console(file=sio, color_system="truecolor").print(
        Traceback.from_exception(
            *exc_info,
            show_locals=False,
        )
    )


def configure_dev_logger(level: int):
    # timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S")

    wrapper = structlog.make_filtering_bound_logger(level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            # timestamper,
            structlog.processors.StackInfoRenderer(),
            # structlog.dev.set_exc_info,
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=rich_traceback,
            ),
        ],
        wrapper_class=wrapper,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


def configure_prod_logger(level: int):
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
