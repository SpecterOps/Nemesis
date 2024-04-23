# Standard Libraries
import asyncio
import signal
from typing import Any, List, Optional
from urllib.parse import urlparse

# 3rd Party Libraries
import structlog
from dependency_injector.wiring import Provide, inject
from nemesiscommon.logging import configure_logger
from nemesiscommon.setupqueues import initRabbitMQ
from nemesiscommon.socketwaiter import SocketWaiter
from nemesiscommon.tasking import TaskDispatcher

from enrichment.containers import Container
from enrichment.settings import EnrichmentSettings

logger: structlog.BoundLogger = structlog.get_logger(module=__name__)


@inject
async def amain(container: Container):
    await container.init_resources()  # type: ignore

    task_list = []
    config = container.config2()

    if config.storage_provider == "s3":
        container.storage_service.override(container.storage_service_s3)

    await initRabbitMQ(str(config.rabbitmq_connection_uri))
    await wait_for_services(config)

    task_names = get_task_names(config, container)

    for name in task_names:
        t = await container.tasks(name)  # type: ignore
        task_list.append(t)

    await logger.ainfo("Starting task dispatcher", tasks=task_names)
    dispatcher = TaskDispatcher(task_list, config.prometheus_port)
    await dispatcher.start()


def get_task_names(config: EnrichmentSettings, container: Container) -> List[str]:
    all_tasks = list(container.tasks.providers.keys())

    if not config.tasks:
        return all_tasks

    excluded_tasks = [t[1:] for t in config.tasks if t.startswith("-")]

    # If there's task exclusions, only return tasks that aren't in the exclusion list
    if excluded_tasks:
        if len(excluded_tasks) != len(config.tasks):
            raise ValueError("Cannot mix specifying both task exclusions and inclusions")

        validate_task_names(excluded_tasks, all_tasks)
        return [t for t in all_tasks if t not in excluded_tasks]

    # Ensure the configured tasks are valid
    validate_task_names(config.tasks, all_tasks)
    return config.tasks


def validate_task_names(input_tasks: List[str], all_tasks: List[str]):
    for t in input_tasks:
        if t not in all_tasks:
            raise ValueError(f"'{t}' is not a valid task name. Possible tasks: {all_tasks.sort()}")


@inject
def main(container: Container, config: EnrichmentSettings = Provide[Container.config2]):
    configure_logger(config.environment, config.log_level, config.log_color_enabled)

    logger = structlog.get_logger(module=__name__)
    loop = asyncio.get_event_loop()

    if config.environment.is_development():
        # loop.set_debug(True)
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


async def wait_for_services(config: EnrichmentSettings) -> None:
    rabbitUri = urlparse(str(config.rabbitmq_connection_uri))
    elasticUri = urlparse(str(config.elasticsearch_url))
    postgresUri = urlparse(str(config.postgres_connection_uri))

    if rabbitUri.hostname is None or elasticUri.hostname is None or postgresUri.hostname is None:
        raise Exception("Invalid connection URI")
    if rabbitUri.port is None or elasticUri.port is None or postgresUri.port is None:
        raise Exception("Invalid connection URI")

    SocketWaiter(rabbitUri.hostname, rabbitUri.port).wait()
    SocketWaiter(elasticUri.hostname, elasticUri.port).wait()
    SocketWaiter(postgresUri.hostname, postgresUri.port).wait()
    await logger.ainfo("All services are online!")
