# Standard Libraries
import asyncio
from abc import ABC, abstractmethod
from typing import List

# 3rd Party Libraries
import structlog
from prometheus_async.aio.web import MetricsHTTPServer, start_http_server

from nemesiscommon.settings import NemesisServiceSettings

logger = structlog.get_logger(__name__)


class TaskInterface(ABC):
    @abstractmethod
    async def run(self) -> None:
        pass

    async def shutdown(self) -> None:
        pass


class TaskDispatcher:
    metrics_server: MetricsHTTPServer
    tasks: List[TaskInterface]
    prometheus_port: int
    environment: NemesisServiceSettings

    def __init__(self, tasks: List[TaskInterface], prometheus_port: int, environment: NemesisServiceSettings) -> None:
        self.tasks = tasks
        self.prometheus_port = prometheus_port
        self.environment = environment

    async def start(self) -> None:
        await logger.ainfo("Application started")

        if self.environment.environment.is_production():
            self.metrics_server = await start_http_server(port=self.prometheus_port)

        await logger.ainfo("Starting services")

        # TODO:
        #  - Switch this to use asyncio.gather due to TaskGroup not behaving nicely when other libraries cancel tasks (*cough* aiohttp *cough).
        #  - Setup an asyncio exception handler to gracefully shutdown/cancel all other tasks
        async with asyncio.TaskGroup() as tg:
            for s in self.tasks:
                service_name = s.__class__.__name__
                logger.info("Starting service", service=s.__class__.__name__)
                tg.create_task(s.run(), name=service_name)

        await logger.ainfo("Application shutting down")

    async def stop(self):
        await logger.ainfo("Stopping application")
        pass
