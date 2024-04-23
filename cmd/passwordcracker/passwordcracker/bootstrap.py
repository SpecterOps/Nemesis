# Standard Libraries
import asyncio
import signal
from typing import Any, Optional
from urllib.parse import urlparse

# 3rd Party Libraries
import structlog
from dependency_injector.wiring import Provide, inject
from nemesiscommon.logging import configure_logger
from nemesiscommon.setupqueues import initRabbitMQ
from nemesiscommon.socketwaiter import SocketWaiter

from passwordcracker.containers import Container
from passwordcracker.settings import PasswordCrackerSettings

logger: structlog.BoundLogger = structlog.get_logger(module=__name__)


@inject
async def amain(container: Container):
    await container.init_resources()  # type: ignore
    config = container.config2()

    await initRabbitMQ(str(config.rabbitmq_connection_uri))
    await wait_for_services(config)

    dispatcher = await container.task_dispatcher()  # type: ignore
    await dispatcher.start()


@inject
def main(container: Container, config: PasswordCrackerSettings = Provide[Container.config2]):
    configure_logger(config.environment, config.log_level, config.log_color_enabled)
    logger = structlog.get_logger(module=__name__)
    loop = asyncio.get_event_loop()

    if config.environment.is_development():
        loop.slow_callback_duration = 1

    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for s in signals:
        loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(container, loop, s)))
    loop.set_exception_handler(handle_exception)

    try:
        task = amain(container)
        loop.run_until_complete(task)
    except asyncio.exceptions.CancelledError:
        logger.debug("Primary App asyncio task cancelled. Application is shutting down.")


async def shutdown(container: Container, loop: asyncio.AbstractEventLoop, signal: Optional[signal.Signals] = None):
    """Cleanup tasks tied to the service's shutdown."""

    if signal:
        logger.info(f"Shutting down due the signal '{signal.name}'...")
    else:
        logger.info("Shutting down...")

    await container.shutdown_resources()  # type: ignore
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    logger.debug(f"Cancelling {len(tasks)} outstanding tasks")
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


async def wait_for_services(config: PasswordCrackerSettings) -> None:
    rabbitUri = urlparse(str(config.rabbitmq_connection_uri))
    postgresUri = urlparse(str(config.postgres_connection_uri))

    if rabbitUri.hostname is None or postgresUri.hostname is None:
        raise Exception("Invalid connection URI")
    if rabbitUri.port is None or postgresUri.port is None:
        raise Exception("Invalid connection URI")

    SocketWaiter(rabbitUri.hostname, rabbitUri.port).wait()
    SocketWaiter(postgresUri.hostname, postgresUri.port).wait()
    await logger.ainfo("All services are online!")
