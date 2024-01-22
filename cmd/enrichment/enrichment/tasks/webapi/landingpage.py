# 3rd Party Libraries
import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi_class.decorators import get
from fastapi_class.routable import Routable
from nemesiscommon.tasking import TaskInterface

logger = structlog.get_logger(module=__name__)


class LandingPageApi(TaskInterface):
    log_level: str

    def __init__(self, log_level: str) -> None:
        self.log_level = log_level

    async def run(self) -> None:
        app = FastAPI()
        routes = LandingPageRoutes()
        app.include_router(routes.router)
        server_config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=9920,
            log_level=self.log_level.lower(),
        )
        server = uvicorn.Server(server_config)
        logger.info("Starting LandingPageAPI", port="9920")
        await server.serve()


class LandingPageRoutes(Routable):
    def __init__(self) -> None:
        super().__init__()

    @get("/", response_class=HTMLResponse)
    async def home(self):
        return """
<html>
    <head>
        <title>Nemesis Services</title>
    </head>
    <body>
        <h1>Nemesis Services</h1>

        <h2>Main Services</h2>
        <a href="/dashboard/" target="_blank"">Dashboard</a><br>
        <a href="/hasura/" target="_blank">Hasura (API)</a><br>
        <a href="/kibana/" target="_blank">Kibana</a><br>
        <a href="/rabbitmq/" target="_blank">RabbitMQ Management UI</a><br>

        <h2>Monitoring</h2>
        <a href="/alertmanager/" target="_blank"">Alertmanager</a><br>
        <a href="/grafana/" target="_blank">Grafana</a><br>
        <a href="/prometheus/graph" target="_blank">Prometheus</a><br>

        <h2>Misc</h2>
        <a href="/elastic/" target="_blank">Elastic</a><br>
        <a href="/yara/" target="_blank">Yara Endpoint</a><br>
        <a href="/crack-list/" target="_blank">Password Cracklist Endpoint</a><br>
    </body>
</html>
        """
