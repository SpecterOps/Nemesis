import functools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ParamSpec, TypeVar
from urllib.parse import urljoin, urlparse

import aiohttp

# Type variables for the decorator
T = TypeVar("T")
P = ParamSpec("P")


@dataclass
class Beacon:
    bid: str
    pbid: str
    pid: int
    process: str
    user: str
    impersonated: str | None
    is_admin: bool
    computer: str
    host: str
    internal: str
    external: str
    os: str
    version: str
    build: int
    charset: str
    system_arch: str
    beacon_arch: str
    session: str
    listener: str
    pivot_hint: str | None
    port: int
    note: str | None
    color: str
    alive: bool
    link_state: str
    last_checkin_time: datetime
    last_checkin_ms: int
    last_checkin_formatted: str
    sleep: int
    jitter: int
    supports_sleep: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Beacon":
        sleep_data = data.get("sleep", {})
        return cls(
            bid=data["bid"],
            pbid=data["pbid"],
            pid=data["pid"],
            process=data["process"],
            user=data["user"],
            impersonated=data.get("impersonated"),
            is_admin=data["isAdmin"],
            computer=data["computer"],
            host=data["host"],
            internal=data["internal"],
            external=data["external"],
            os=data["os"],
            version=data["version"],
            build=data["build"],
            charset=data["charset"],
            system_arch=data["systemArch"],
            beacon_arch=data["beaconArch"],
            session=data["session"],
            listener=data["listener"],
            pivot_hint=data.get("pivotHint"),
            port=data["port"],
            note=data.get("note"),
            color=data["color"],
            alive=data["alive"],
            link_state=data["linkState"],
            last_checkin_time=datetime.fromisoformat(data["lastCheckinTime"].replace("Z", "+00:00")),
            last_checkin_ms=data["lastCheckinMs"],
            last_checkin_formatted=data["lastCheckinFormatted"],
            sleep=sleep_data.get("sleep", 0),
            jitter=sleep_data.get("jitter", 0),
            supports_sleep=data["supportsSleep"],
        )


@dataclass
class Download:
    id: str
    bid: str
    name: str
    path: str
    size: int
    timestamp: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Download":
        return cls(
            id=data["id"],
            bid=data["bid"],
            name=data["name"],
            path=data["path"],
            size=data["size"],
            timestamp=datetime.fromtimestamp(data["timestamp"] / 1000),  # Convert milliseconds to seconds
        )


class CobaltStrikeClient:
    def __init__(self, base_url: str, verify_ssl: bool = False, validate_https: bool = True):
        """
        Initialize the Cobalt Strike C2 Client client.

        Args:
            base_url: The base URL of the API server (default: https://localhost:11000)
            verify_ssl: Whether to verify SSL certificates (default: False)
            validate_https: Whether to validate HTTPS usage (default: True)

        Raises:
            ValueError: If the base_url contains a path, query parameters, or fragment
            ValueError: If validate_https is True and the URL scheme is not HTTPS
        """
        self.logger = logging.getLogger(__name__)

        # Parse and validate the base URL
        parsed = urlparse(base_url)
        if any([parsed.path not in ["", "/"], parsed.params, parsed.query, parsed.fragment]):
            raise ValueError("base_url must not contain path, parameters, query string, or fragment")

        # Validate HTTPS usage if required
        # if validate_https and parsed.scheme != "https":
        #     raise ValueError("HTTPS is required when validate_https is True")

        # Ensure the base_url doesn't end with a slash
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self._session = None
        self._access_token = None
        self._stored_credentials = None  # Store credentials for reauthentication

    async def __aenter__(self):
        """Context manager entry - creates the aiohttp session."""
        # Set timeout for all requests (30 seconds total, 10 seconds for connection)
        timeout = aiohttp.ClientTimeout(total=30, connect=10)

        # Create SSL context based on verify_ssl setting
        import ssl
        ssl_context = ssl.create_default_context()
        if not self.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self._session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(),
            connector=aiohttp.TCPConnector(ssl=ssl_context if self.verify_ssl else False),
            timeout=timeout
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - closes the aiohttp session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def _reauthenticate(self) -> bool:
        """
        Attempt to reauthenticate using stored credentials.

        Returns:
            bool: True if reauthentication was successful
        """
        if not self._stored_credentials:
            self.logger.error("No stored credentials available for reauthentication")
            return False

        self.logger.info("Attempting reauthentication")
        return await self.authenticate(self._stored_credentials["username"], self._stored_credentials["password"])

    def requires_auth(func: Callable[P, T]) -> Callable[P, T]:
        """
        Decorator that handles token expiration and reauthentication.
        """

        @functools.wraps(func)
        async def wrapper(self: "CobaltStrikeClient", *args: P.args, **kwargs: P.kwargs) -> T:
            try:
                return await func(self, *args, **kwargs)
            except aiohttp.ClientResponseError as e:
                if e.status == 401:  # Unauthorized - token might be expired
                    self.logger.info("Token appears to be expired, attempting reauthentication")
                    if await self._reauthenticate():
                        self.logger.info("Reauthentication successful, retrying original request")
                        return await func(self, *args, **kwargs)
                    else:
                        self.logger.error("Reauthentication failed")
                        raise
                raise

        return wrapper

    async def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with the API using username and password.

        Args:
            username: The username to authenticate with
            password: The password for authentication

        Returns:
            bool: True if authentication was successful
        """

        if not self._session:
            raise RuntimeError("Client session not established")

        auth_url = urljoin(self.base_url, "/api/auth/login")
        data = {"username": username, "password": password, "duration_ms": 86400000}

        try:
            self.logger.info(f"Attempting authentication for user: {username}")
            async with self._session.post(auth_url, json=data) as response:
                if response.status == 200:
                    auth_response = await response.json()
                    token = auth_response.get("access_token")

                    if token:
                        self._access_token = token

                        # Set the Authorization header for future requests
                        self._session.headers.update({"Authorization": f"Bearer {token}"})

                        self._stored_credentials = {"username": username, "password": password}
                        self.logger.info("Authentication successful")
                        return True
                    else:
                        self.logger.warning("No access token in response")
                        return False

                self.logger.warning(f"Authentication failed with status code: {response.status}")
                return False
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            raise

    @requires_auth
    async def get_beacons(self) -> list[Beacon]:
        """Get list of all beacons."""

        if not self._session:
            raise RuntimeError("Client session not established")

        try:
            self.logger.info("Fetching beacons list")
            async with self._session.get(urljoin(self.base_url, "/api/v1/beacons")) as response:
                if response.status == 200:
                    data = await response.json()
                    beacons = [Beacon.from_dict(beacon) for beacon in data]
                    self.logger.info(f"Successfully retrieved {len(beacons)} beacons")
                    return beacons
                self.logger.error(f"Failed to get beacons, status code: {response.status}")
                response.raise_for_status()
        except Exception as e:
            self.logger.error(f"Error getting beacons: {str(e)}")
            raise

    @requires_auth
    async def get_downloads(self) -> list[Download]:
        """Get list of all downloads."""

        if not self._session:
            raise RuntimeError("Client session not established")

        try:
            self.logger.debug("Fetching downloads list")
            async with self._session.get(urljoin(self.base_url, "/api/v1/data/downloads")) as response:
                if response.status == 200:
                    data = await response.json()
                    downloads = [Download.from_dict(download) for download in data]
                    self.logger.debug(f"Successfully retrieved {len(downloads)} downloads")
                    return downloads

                self.logger.error(f"Failed to get downloads, status code: {response.status}")
                response.raise_for_status()
        except Exception as e:
            self.logger.error(f"Error getting downloads: {str(e)}")
            raise

    @requires_auth
    async def download_file(self, download_uid: str, output_path: str) -> bool:
        """
        Download a file using its UID and save it to the specified path.

        Args:
            download_uid: The UID of the download
            output_path: The local path where the file should be saved

        Returns:
            bool: True if download was successful

        Raises:
            aiohttp.ClientResponseError: If the server returns an error response
            IOError: If there's an error writing the file
        """
        if not self._session:
            raise RuntimeError("Client session not established")

        try:
            self.logger.debug(f"Downloading file with UID: {download_uid}")
            download_url = urljoin(self.base_url, f"/api/v1/data/downloads/{download_uid}")

            async with self._session.get(download_url) as response:
                if response.status == 200:
                    with open(output_path, "wb") as f:
                        # Stream the download to avoid loading entire file into memory
                        async for chunk in response.content.iter_chunked(8192):
                            f.write(chunk)

                    self.logger.debug(f"Successfully downloaded file to: {output_path}")
                    return True

                self.logger.error(f"Failed to download file, status code: {response.status}")
                response.raise_for_status()
                return False

        except OSError as e:
            self.logger.error(f"Error writing file to {output_path}: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Error downloading file: {str(e)}")
            raise
