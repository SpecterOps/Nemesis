# Standard library imports
import asyncio
import logging
import tempfile
import time
from contextlib import nullcontext
from pathlib import Path
from urllib.parse import ParseResult, urlparse, urlunparse

# Third-party imports
import aiohttp
from cli.config import NemesisConfig, PasswordCredential, StrictHttpUrl
from cli.mythic_connector.config import Settings, TokenCredential
from cli.mythic_connector.db import Database, DatabaseError
from cli.mythic_connector.handlers import FileHandler, PermanentMythicError
from cli.mythic_connector.logger import get_logger
from cli.nemesis_client import NemesisClient, PreviewNemesisClient
from cli.preflight import check_nemesis_availability
from gql.transport.exceptions import TransportClosed, TransportServerError
from mythic import mythic
from websockets.exceptions import ConnectionClosed

logger = get_logger(__name__)

RECONNECT_DELAYS_SEC = (1, 2, 4, 8, 16, 30)


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
        self.dry_run = False

    async def initialize_db(self) -> bool:
        """Initialize the database connection.

        Raises:
            Configuration and authentication failures are fatal; network failures are
            propagated for the reconnect supervisor to classify.
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
            url: ParseResult = urlparse(self.cfg.mythic.url)
            ssl = url.scheme == "https"
            if url.scheme not in ("http", "https"):
                raise ValueError("Mythic URL must use http or https")
            if not url.hostname:
                raise ValueError(f"Invalid Mythic URL (missing hostname): {self.cfg.mythic.url}")
            port = url.port or (443 if ssl else 80)
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.cfg.networking.timeout_sec)
            ) as session:
                async with session.get(
                    self.cfg.mythic.url,
                    ssl=self.cfg.networking.validate_https_certs if ssl else False,
                ) as resp:
                    if resp.status >= 500:
                        raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=resp.status)
                    if resp.status in (401, 403):
                        raise ValueError(f"Mythic authorization rejected ({resp.status})")

            # Authenticate
            hostname = url.hostname
            if isinstance(self.cfg.mythic.credential, TokenCredential):
                self.mythic = await mythic.login(
                    apitoken=self.cfg.mythic.credential.token,
                    server_ip=hostname,
                    server_port=port,
                    ssl=ssl,
                    logging_level=logging.WARNING,
                    timeout=self.cfg.networking.timeout_sec,
                )
            else:
                self.mythic = await mythic.login(
                    username=self.cfg.mythic.credential.username,
                    password=self.cfg.mythic.credential.password,
                    server_ip=hostname,
                    server_port=port,
                    ssl=ssl,
                    logging_level=logging.WARNING,
                    timeout=self.cfg.networking.timeout_sec,
                )

            probe = await mythic.execute_custom_query(
                mythic=self.mythic,
                query="""query NemesisMythicPreflight {
                  meHook { status error current_operation_id current_operation }
                  filemeta(limit:1) { id }
                }""",
            )
            me = probe.get("meHook") or {}
            if not me or me.get("status") != "success" or me.get("error"):
                raise ValueError(
                    f"Mythic authentication or GraphQL authorization failed: {me.get('error', 'invalid meHook response')}"
                )
            selected = me.get("current_operation_id")
            if not isinstance(selected, int) or selected <= 0:
                raise ValueError("Mythic user has no selected operation")
            self.mythic.current_operation_id = selected
            # The query itself validates filemeta schema/read access even when no records exist.
            if not isinstance(probe.get("filemeta"), list):
                raise ValueError("Mythic GraphQL authorization denied filemeta access")

            return True

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(
                "Mythic initialization failed for %s (project %s): %s",
                self.cfg.mythic.url,
                self.cfg.project,
                type(e).__name__,
            )
            raise

    def _create_nemesis_client(self) -> NemesisClient:
        cfg = NemesisConfig(
            url=StrictHttpUrl(urlunparse(self.cfg.nemesis.url)),
            credential=PasswordCredential(
                username=self.cfg.nemesis.credential.username,
                password=self.cfg.nemesis.credential.password,
            ),
        )
        return NemesisClient(
            cfg, verify_ssl=self.cfg.networking.validate_https_certs, connect_timeout=self.cfg.networking.timeout_sec
        )

    def initialize_handlers(self) -> None:
        """Initialize the Nemesis client and data handlers."""

        if self.mythic is None:
            raise RuntimeError("Mythic client not initialized")
        if self.db is None:
            raise RuntimeError("Database not initialized")

        if self.nemesis is None:
            self.nemesis = self._create_nemesis_client()
        self.file_handler = FileHandler(self.mythic, self.nemesis, self.db, self.cfg)
        # self.browser_handler = FileBrowserHandler(self.mythic, self.nemesis, self.db, self.cfg)

    async def run(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        original_path = self.cfg.db.path
        with tempfile.TemporaryDirectory(prefix="nemesis-mythic-dryrun-") if dry_run else nullcontext() as tempdir:
            try:
                if dry_run:
                    self.cfg.db.path = str(Path(tempdir) / "state.db")
                client = PreviewNemesisClient() if dry_run else self._create_nemesis_client()
                async with client:
                    self.nemesis = client
                    await self._run_with_nemesis()
            finally:
                self.cfg.db.path = original_path

    async def _run_with_nemesis(self) -> None:
        """Main service loop.

        This method manages the lifecycle of the service, including initialization,
        maintaining connections, and handling errors.
        """
        if not self.dry_run:
            await check_nemesis_availability(self.nemesis, timeout=self.cfg.networking.timeout_sec, logger=logger)
        else:
            logger.info("Dry run enabled; Nemesis preflight and uploads are disabled")
        if not await self.initialize_db():
            raise RuntimeError("Database initialization failed")
        delay_index = 0
        try:
            while True:
                session_started = time.monotonic()
                try:
                    if not await self.initialize_mythic():
                        raise RuntimeError("Mythic authentication or preflight failed")
                    self.initialize_handlers()
                    logger.info("Starting data synchronization")
                    await self.file_handler.subscribe()
                    logger.warning("Mythic subscription ended; reconnecting")
                except asyncio.CancelledError:
                    raise
                except (DatabaseError, ValueError, TypeError):
                    raise
                except Exception as exc:
                    if isinstance(exc, PermanentMythicError):
                        raise
                    if not _is_transient_mythic_error(exc):
                        raise RuntimeError(
                            f"Permanent Mythic configuration/authentication/schema error ({type(exc).__name__})"
                        ) from exc
                    logger.warning("Mythic session ended; reconnecting after transient error (%s)", type(exc).__name__)
                if time.monotonic() - session_started >= 60:
                    delay_index = 0
                delay = RECONNECT_DELAYS_SEC[min(delay_index, len(RECONNECT_DELAYS_SEC) - 1)]
                await asyncio.sleep(delay)
                delay_index += 1
        finally:
            if self.db:
                self.db.close()


def _is_transient_mythic_error(exc: Exception) -> bool:
    if isinstance(exc, aiohttp.ClientConnectorCertificateError):
        return False
    if isinstance(exc, (TransportClosed, ConnectionClosed)):
        return True
    if isinstance(exc, TransportServerError):
        return exc.code is not None and (exc.code >= 500 or exc.code in (408, 425, 429))
    if isinstance(exc, (aiohttp.ClientConnectionError, aiohttp.ClientPayloadError, asyncio.TimeoutError, OSError)):
        return True
    if isinstance(exc, aiohttp.ClientResponseError):
        return exc.status >= 500 or exc.status in (408, 425, 429)
    return False
