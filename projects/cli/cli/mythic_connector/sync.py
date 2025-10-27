# Standard library imports
import asyncio
import logging
from urllib.parse import ParseResult, urlparse, urlunparse

# Third-party imports
import aiohttp
from cli.config import NemesisConfig, PasswordCredential
from cli.mythic_connector.config import Settings, TokenCredential
from cli.mythic_connector.db import Database
from cli.mythic_connector.handlers import FileHandler
from cli.mythic_connector.logger import get_logger
from cli.nemesis_client import NemesisClient
from mythic import mythic

logger = get_logger(__name__)


class SyncService:
    """Main service class that coordinates all synchronization activities.

    This class manages the lifecycle of the synchronization service, including
    startup, authentication, and maintaining connections to both Mythic and
    Nemesis services.
    """

    def __init__(self, config: Settings) -> None:
        """Initialize the sync service.

        Args:
            config: Application configuration
        """
        self.cfg = config
        self.db = None
        self.mythic = None
        self.nemesis = None
        self.file_handler = None
        self.browser_handler = None

    async def initialize_db(self) -> bool:
        """Initialize the database connection.

        Returns:
            True if successful, False otherwise
        """
        self.db = Database(self.cfg.db.path)
        return True

    async def initialize_mythic(self) -> bool:
        """Initialize the Mythic connection and authenticate.

        Returns:
            True if successful, False otherwise
        """
        try:
            # Test connection
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.cfg.mythic.url,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=self.cfg.networking.timeout_sec),
                ) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status}")

            # Authenticate
            url: ParseResult = urlparse(self.cfg.mythic.url)
            if isinstance(self.cfg.mythic.credential, TokenCredential):
                self.mythic = await mythic.login(
                    apitoken=self.cfg.mythic.credential.token,
                    server_ip=url.hostname,
                    server_port=url.port,
                    ssl=True,
                    logging_level=logging.WARNING,
                    timeout=10,
                )
            else:
                self.mythic = await mythic.login(
                    username=self.cfg.mythic.credential.username,
                    password=self.cfg.mythic.credential.password,
                    server_ip=url.hostname,
                    server_port=url.port,
                    ssl=True,
                    logging_level=logging.WARNING,
                    timeout=10,
                )

            return True

        except Exception as e:
            logger.error(
                f"Mythic initialization error. Mythic URL: {self.cfg.mythic.url}. Project: {self.cfg.project}. Error: {e}"
            )
            return False

    def initialize_handlers(self) -> None:
        """Initialize the Nemesis client and data handlers."""

        cfg = NemesisConfig(
            url=urlunparse(self.cfg.nemesis.url),
            credential=PasswordCredential(
                username=self.cfg.nemesis.credential.username,
                password=self.cfg.nemesis.credential.password,
            ),
        )

        self.nemesis = NemesisClient(cfg)
        self.file_handler = FileHandler(self.mythic, self.nemesis, self.db, self.cfg)
        # self.browser_handler = FileBrowserHandler(self.mythic, self.nemesis, self.db, self.cfg)

    async def run(self) -> None:
        """Main service loop.

        This method manages the lifecycle of the service, including initialization,
        maintaining connections, and handling errors.
        """
        try:
            # Initialize components
            if not await self.initialize_db():
                raise Exception("Database initialization failed")

            if not await self.initialize_mythic():
                raise Exception("Failed to initialize Mythic connection")

            self.initialize_handlers()

            # Start subscriptions
            logger.info("Starting data synchronization")
            await self.file_handler.subscribe()
            # await asyncio.gather(self.file_handler.subscribe())
            # await asyncio.gather(self.file_handler.subscribe(), self.browser_handler.subscribe())

        except Exception as e:
            logger.exception(f"Service error: {e}")

        finally:
            # Clean up before retry
            if self.db:
                self.db.close()

            await asyncio.sleep(self.cfg.networking.timeout_sec)
