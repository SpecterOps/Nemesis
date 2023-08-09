# Standard Libraries
import asyncio
import signal
from typing import Any, Optional

# 3rd Party Libraries
import structlog
from nemesiscommon.logging import configure_logger

from nlp.app import App
from nlp.settings import config

configure_logger(False, config.log_level, config.environment.value)
logger = structlog.get_logger(module=__name__)


def main():
    loop = asyncio.get_event_loop()

    if config.environment.is_development():
        # loop.set_debug(True)
        loop.slow_callback_duration = 1

    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for s in signals:
        loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(loop, s)))
    loop.set_exception_handler(handle_exception)

    app = App(config)
    task = app.start()
    loop.run_until_complete(task)


async def shutdown(
    loop: asyncio.AbstractEventLoop, signal: Optional[signal.Signals] = None
):
    """Cleanup tasks tied to the service's shutdown."""

    if signal:
        await logger.ainfo(f"Shutting down due the signal '{signal.name}'...")
    else:
        await logger.ainfo("Shutting down...")

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    await logger.ainfo(f"Cancelling {len(tasks)} outstanding tasks")
    [task.cancel() for task in tasks]

    await asyncio.gather(*tasks)

    loop.stop()


def handle_exception(loop: asyncio.AbstractEventLoop, context: dict[str, Any]):
    # context["message"] will always be there; but context["exception"] may not

    e = context.get("exception", None)
    msg = context.get("message")

    if "exception" in context:
        logger.error(
            "Unhandled global exception",
            exception=str(e),
            exception_message=msg,
        )
    else:
        logger.error("Unhandled global exception", exception_message=msg)

    # logger.info("Shutting down...")
    # asyncio.create_task(shutdown(loop))


if __name__ == "__main__":
    main()
