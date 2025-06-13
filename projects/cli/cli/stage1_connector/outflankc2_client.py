import functools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, ParamSpec, TypeVar
from urllib.parse import urljoin, urlparse

import aiohttp

# Type variables for the decorator
T = TypeVar("T")
P = ParamSpec("P")


@dataclass
class Implant:
    uid: str
    version: str
    hostname: str
    username: str
    os: str
    first_seen: datetime
    last_seen: datetime
    checkin_count: int
    privilege: int
    pid: int
    ppid: int
    proc_name: str
    pproc_name: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Implant":
        return cls(
            uid=data["uid"],
            version=data["version"],
            hostname=data["hostname"],
            username=data["username"],
            os=data["os"],
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            checkin_count=data["checkin_count"],
            privilege=data["privilege"],
            pid=data["pid"],
            ppid=data["ppid"],
            proc_name=data["proc_name"],
            pproc_name=data["pproc_name"],
        )


@dataclass
class Download:
    uid: str
    timestamp: datetime
    path: str
    name: str
    size: int
    progress: float
    task_uid: str
    implant_uid: str
    implant_username: str
    implant_hostname: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Download":
        return cls(
            uid=data["uid"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            path=data["path"],
            name=data["name"],
            size=data["size"],
            progress=data["progress"],
            task_uid=data["task_uid"],
            implant_uid=data["implant_uid"],
            implant_username=data["implant"]["username"],
            implant_hostname=data["implant"]["hostname"],
        )


class OutflankC2Client:
    def __init__(self, base_url: str, verify_ssl: bool = False, validate_https: bool = True):
        """
        Initialize the Outflank C2 Client client.

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
        self._session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(), connector=aiohttp.TCPConnector(ssl=self.verify_ssl)
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
        return await self.authenticate(self._stored_credentials["username"], self._stored_credentials["join_key"])

    def requires_auth(func: Callable[P, T]) -> Callable[P, T]:
        """
        Decorator that handles token expiration and reauthentication.
        """

        @functools.wraps(func)
        async def wrapper(self: "OutflankC2Client", *args: P.args, **kwargs: P.kwargs) -> T:
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

    async def authenticate(self, username: str, join_key: str) -> bool:
        """
        Authenticate with the API using username and join key.

        Args:
            username: The username to authenticate with
            join_key: The join key for authentication

        Returns:
            bool: True if authentication was successful
        """

        if not self._session:
            raise RuntimeError("Client session not established")

        auth_url = urljoin(self.base_url, "/api/auth")
        data = {"username": username, "join_key": join_key}

        try:
            self.logger.info(f"Attempting authentication for user: {username}")
            async with self._session.post(auth_url, data=data, allow_redirects=False) as response:
                if response.status == 302:
                    # Get the Set-Cookie header directly
                    set_cookie_header = response.headers.get("Set-Cookie")
                    if set_cookie_header:
                        # Extract token from Set-Cookie header
                        token = set_cookie_header.split(";")[0].split("=")[1]
                        self._access_token = token

                        # Create a proper cookie
                        self._session.cookie_jar.update_cookies({"access_token_cookie": token}, response.url)

                        # Add it as a default header for future requests
                        self._session.headers.update({"Cookie": f"access_token_cookie={token}"})

                        self._stored_credentials = {"username": username, "join_key": join_key}
                        self.logger.info("Authentication successful")
                        return True
                self.logger.warning(f"Authentication failed with status code: {response.status}")
                return False
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            raise

    @requires_auth
    async def get_current_user(self) -> Optional[str]:
        """Get the currently authenticated username."""
        if not self._access_token:
            self.logger.warning("No access token available")
            return None

        try:
            self.logger.info("Fetching current user information")
            async with self._session.get(urljoin(self.base_url, "/api/auth")) as response:
                if response.status == 200:
                    data = await response.json()
                    self.logger.info(f"Successfully retrieved user: {data['username']}")
                    return data["username"]
                self.logger.warning(f"Failed to get user info, status code: {response.status}")
                return None
        except Exception as e:
            self.logger.error(f"Error getting current user: {str(e)}")
            raise

    @requires_auth
    async def get_project_info(self) -> dict[str, Any]:
        """Get current project information."""

        if not self._session:
            raise RuntimeError("Client session not established")

        try:
            self.logger.info("Fetching project information")
            async with self._session.get(urljoin(self.base_url, "/api/project")) as response:
                if response.status == 200:
                    data = await response.json()
                    self.logger.info(f"Successfully retrieved project info: {data['name']}")
                    return data
                self.logger.error(f"Failed to get project info, status code: {response.status}")
                response.raise_for_status()
        except Exception as e:
            self.logger.error(f"Error getting project info: {str(e)}")
            raise

    @requires_auth
    async def get_implants(self) -> list[Implant]:
        """Get list of all implants."""

        if not self._session:
            raise RuntimeError("Client session not established")

        try:
            self.logger.info("Fetching implants list")
            async with self._session.get(urljoin(self.base_url, "/api/implants")) as response:
                if response.status == 200:
                    data = await response.json()
                    implants = [Implant.from_dict(implant) for implant in data]
                    self.logger.info(f"Successfully retrieved {len(implants)} implants")
                    return implants
                self.logger.error(f"Failed to get implants, status code: {response.status}")
                response.raise_for_status()
        except Exception as e:
            self.logger.error(f"Error getting implants: {str(e)}")
            raise

    @requires_auth
    async def get_downloads(self) -> list[Download]:
        """Get list of all downloads."""

        if not self._session:
            raise RuntimeError("Client session not established")

        try:
            self.logger.debug("Fetching downloads list")
            async with self._session.get(urljoin(self.base_url, "/api/downloads/views/default")) as response:
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
            download_url = urljoin(self.base_url, f"/api/downloads/{download_uid}")

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
