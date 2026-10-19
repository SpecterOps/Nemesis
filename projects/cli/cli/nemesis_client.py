import asyncio
import hashlib
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

import httpx
from cli.config import NemesisConfig
from common.models2.api import (
    APIInfo,
    ErrorResponse,
    FileMetadata,
    FileWithMetadataResponse,
    HealthResponse,
    YaraReloadResponse,
)

logger = logging.getLogger(__name__)


class PreviewUploadResult:
    """Local dry-run result; deliberately contains no generated Nemesis object ID."""

    def __init__(self, size_bytes: int, sha256: str) -> None:
        self.size_bytes = size_bytes
        self.sha256 = sha256


class PreviewNemesisClient:
    """Upload-compatible local preview backend used by connector dry runs."""

    async def __aenter__(self) -> "PreviewNemesisClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def get_health(self, timeout: float = 10) -> HealthResponse:
        raise RuntimeError("PreviewNemesisClient has no Nemesis health endpoint")

    async def post_file(self, file: BinaryIO | str | Path, metadata: FileMetadata) -> PreviewUploadResult:
        path = Path(file) if isinstance(file, (str, Path)) else None
        if path is None:
            raise TypeError("Preview uploads require a file path")
        hash_task = asyncio.create_task(asyncio.to_thread(_hash_file, path))
        try:
            size, digest = await asyncio.shield(hash_task)
        except asyncio.CancelledError:
            await hash_task
            raise
        logger.info(
            "WOULD UPLOAD path=%s project=%s source=%s size=%d sha256=%s",
            metadata.path,
            metadata.project,
            metadata.source,
            size,
            digest,
        )
        return PreviewUploadResult(size, digest)


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


class NemesisClient:
    """Async HTTP client for Nemesis API operations."""

    def __init__(
        self,
        cfg: NemesisConfig,
        *,
        verify_ssl: bool = True,
        connect_timeout: float = 10,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.cfg = cfg
        self.verify_ssl = verify_ssl
        self.connect_timeout = connect_timeout
        self._transport = transport
        self._http: httpx.AsyncClient | None = None
        self._upload_slots = asyncio.Semaphore(4)

    async def __aenter__(self) -> "NemesisClient":
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        self._http = httpx.AsyncClient(
            auth=(self.cfg.credential.username, self.cfg.credential.password),
            verify=self.verify_ssl,
            timeout=httpx.Timeout(
                self.connect_timeout, connect=self.connect_timeout, read=520.0, write=520.0, pool=self.connect_timeout
            ),
            limits=limits,
            transport=self._transport,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._http is not None:
            client, self._http = self._http, None
            await client.aclose()

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            raise RuntimeError("NemesisClient must be used inside 'async with'")
        return self._http

    def _ensure_open(self) -> None:
        if self._http is None:
            raise RuntimeError("NemesisClient must be used inside 'async with'")

    def create_file_metadata(self, path: str, agent_id: str, project: str, source: str | None = None) -> FileMetadata:
        now = datetime.now(UTC)
        return FileMetadata(
            agent_id=agent_id,
            source=source,
            project=project,
            timestamp=now,
            expiration=now.replace(year=now.year + 1),
            path=path,
        )

    async def _request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        for attempt in range(3):
            try:
                return await self.http.request(method, url, **kwargs)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                if attempt == 2:
                    raise
                logger.warning(
                    "Nemesis %s connection failed; retrying in %s second(s) (%s/3)", method, attempt + 1, attempt + 2
                )
                await asyncio.sleep(attempt + 1)
        raise AssertionError("unreachable")

    async def post_file(
        self, file: BinaryIO | str | Path, metadata: FileMetadata
    ) -> FileWithMetadataResponse | ErrorResponse:
        self._ensure_open()
        if not metadata:
            raise ValueError("File metadata is required")
        owned = isinstance(file, (str, Path))
        stream: BinaryIO | None = None
        try:
            if owned:
                path = Path(file)
                if not path.exists():
                    raise FileNotFoundError(f"File not found: {path}")
                if not os.access(path, os.R_OK):
                    raise PermissionError(f"No read permission for {path}")
                stream = path.open("rb")
            else:
                stream = file
            async with self._upload_slots:
                response = await self._request(
                    "POST",
                    f"{self.cfg.url}/api/files",
                    files={
                        "file": ("file", stream, "application/octet-stream"),
                        "metadata": (None, metadata.model_dump_json(), "application/json"),
                    },
                    timeout=httpx.Timeout(520.0, connect=self.connect_timeout, pool=self.connect_timeout),
                )
            if response.status_code != 200:
                return ErrorResponse(detail=f"Error uploading file to Nemesis: {response.status_code}")
            return FileWithMetadataResponse(**response.json())
        except asyncio.CancelledError:
            raise
        except (FileNotFoundError, PermissionError) as exc:
            logger.error("File access error uploading to Nemesis: %s", exc)
            return ErrorResponse(detail=str(exc))
        except Exception as exc:
            logger.error("Upload request to Nemesis failed: %s", type(exc).__name__)
            return ErrorResponse(detail=f"Upload failed: {exc}")
        finally:
            if owned and stream is not None:
                stream.close()

    async def get_health(self, timeout: float = 10) -> HealthResponse | ErrorResponse:
        self._ensure_open()
        try:
            response = await self._request("GET", f"{self.cfg.url}/api/system/health", timeout=httpx.Timeout(timeout))
            if response.status_code != 200:
                return ErrorResponse(detail=f"Error getting health status: {response.status_code}")
            return HealthResponse(**response.json())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Health request to Nemesis failed: %s", type(exc).__name__)
            return ErrorResponse(detail=f"Error getting health status: {exc}")

    async def get_api_info(self) -> APIInfo | ErrorResponse:
        self._ensure_open()
        try:
            response = await self._request("GET", f"{self.cfg.url}/api/")
            return (
                APIInfo(**response.json())
                if response.status_code == 200
                else ErrorResponse(detail=f"Error getting API info: {response.status_code}")
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return ErrorResponse(detail=f"Error getting API info: {exc}")

    async def reload_yara_rules(self) -> YaraReloadResponse | ErrorResponse:
        self._ensure_open()
        try:
            response = await self._request("POST", f"{self.cfg.url}/api/yara/reload")
            return (
                YaraReloadResponse(**response.json())
                if response.status_code == 200
                else ErrorResponse(detail=f"Error reloading Yara rules: {response.status_code}")
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return ErrorResponse(detail=f"Error reloading Yara rules: {exc}")
