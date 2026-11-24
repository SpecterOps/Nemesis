import asyncio
import base64
import json
import os
import tempfile
import time
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import aiohttp
import urllib3
from cli.c2_metadata import collection_times
from cli.mythic_connector import tls
from cli.mythic_connector.config import (
    DEFAULT_MAX_PENDING_SUBSCRIPTIONS,
    DEFAULT_PENDING_GIVE_UP_DAYS,
    Settings,
)
from cli.mythic_connector.db import Database, DatabaseError
from cli.mythic_connector.logger import get_logger

# from cli.mythic_connector.nemesis import NemesisClient
from cli.nemesis_client import PreviewUploadResult, UploadClient
from common.models2.api import FileMetadata, FileWithMetadataResponse
from gql.transport.exceptions import TransportClosed
from mythic import mythic, mythic_classes

logger = get_logger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PENDING_BATCH_SIZE = 100
RETRY_DELAYS_SEC = (5, 10, 20, 40, 80, 160, 300)
# Columns read for every file record; chunks_received/total_chunks are selectable by every Mythic role.
FILE_FIELDS = (
    "id agent_file_id deleted complete filename_text full_remote_path_text host timestamp chunks_received total_chunks"
)
# Allow this long without a byte before a download stalls; the whole transfer has no total limit.
DOWNLOAD_READ_TIMEOUT_SEC = 300
# A complete file whose download keeps returning 404 is given up after this many attempts.
MAX_MISSING_ATTEMPTS = 3
# Rows at or below the discovery cursor are re-checked this often, within this many IDs, to catch
# inserts that committed after a higher ID was already streamed.
RECONCILE_INTERVAL_SEC = 300
RECONCILE_ID_WINDOW = 1000
# Pending files that don't fit in the capped live-query subscriptions are polled this often.
OVERFLOW_POLL_INTERVAL_SEC = 30
# The pending worker wakes at least this often to give up on stalled downloads.
STALL_CHECK_INTERVAL_SEC = 3600


class PermanentMythicError(RuntimeError):
    """Mythic rejected the configured authentication or request permanently."""


class FileUnavailableError(FileNotFoundError):
    """A previously discovered Mythic file UUID is no longer downloadable."""


class FileTooLargeError(ValueError):
    """A Mythic file exceeds the configured Nemesis max_file_size."""


def _decode_text(value: str | None) -> str:
    if not value:
        return ""
    return base64.b64decode(value).decode("utf-8")


def _remote_path(file_meta: dict[str, Any], file_name: str, full_path: str) -> str:
    """Path to report to Nemesis. Mythic leaves full_remote_path empty for screenshots and for agents that send
    only a file name, so fall back to the file name (or the agent file ID if Mythic has no name either)."""
    return full_path or file_name or str(file_meta.get("agent_file_id") or "")


def _parse_mythic_timestamp(value: Any) -> datetime | None:
    """Mythic stores filemeta.timestamp as naive UTC; return None if it can't be parsed."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _canonical_mythic_url(value: str) -> str:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parsed.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{port}"


class FileHandler:
    """Handles synchronization of downloaded files from Mythic to Nemesis.

    This class manages the processing of file downloads, including tracking
    which files have been processed and uploading them to Nemesis. It uses
    a subscription-based approach to receive new file downloads from Mythic
    in real-time and processes them sequentially.
    """

    def __init__(self, mythic: mythic_classes.Mythic, nemesis: UploadClient, db: Database, config: Settings):
        """Initialize the file handler.

        Args:
            mythic: Authenticated Mythic client instance
            nemesis: Nemesis API client
            db: Database connection
            config: Application configuration
        """
        self.mythic = mythic
        self.nemesis = nemesis
        self.db = db
        self.cfg = config
        self._successful_files_count = 0
        self._total_files_count = 0
        self._pending_changed = asyncio.Event()
        self._metadata_changed = asyncio.Event()
        self._pending_metadata: dict[int, dict[str, Any]] = {}
        self._overflow_ids: set[int] = set()
        sync_cfg = getattr(config, "sync", None)
        self.give_up_sec = getattr(sync_cfg, "pending_give_up_days", DEFAULT_PENDING_GIVE_UP_DAYS) * 86400
        self.max_subscriptions = getattr(sync_cfg, "max_pending_subscriptions", DEFAULT_MAX_PENDING_SUBSCRIPTIONS)
        self.operation_id = str(getattr(mythic, "current_operation_id", ""))
        self.state_prefix = f"mythic:v2:{_canonical_mythic_url(self.cfg.mythic.url)}:{self.operation_id}:"

    def _convert_timestamp(self, timestamp: str, days_to_add: int = 0) -> str:
        """Convert timestamp to a standard format.

        Args:
            timestamp: Input timestamp string
            days_to_add: Optional number of days to add

        Returns:
            Formatted timestamp string
        """
        dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")
        if days_to_add:
            dt += timedelta(days=days_to_add)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _build_metadata(self, file_meta: dict[str, Any]) -> dict[str, Any]:
        """Build metadata dictionary for Nemesis.

        Args:
            file_meta: File metadata from Mythic

        Returns:
            Formatted metadata dictionary
        """
        return {
            "agent_id": self.cfg.mythic.agent_id,
            "agent_type": "mythic",
            "automated": True,
            "data_type": "file_data",
            "expiration": self._convert_timestamp(file_meta["timestamp"], self.cfg.nemesis.expiration_days),
            "project": file_meta["task"]["callback"]["operation"]["name"],
            "timestamp": self._convert_timestamp(file_meta["timestamp"]),
        }

    def _build_file_data(self, file_meta: dict[str, Any], file_size: int, nemesis_id: str) -> dict[str, Any]:
        """Build file data dictionary for Nemesis.

        Args:
            file_meta: File metadata from Mythic
            file_size: Size of the file in bytes
            nemesis_id: Nemesis object ID

        Returns:
            Formatted file data dictionary
        """
        return {
            "path": base64.b64decode(file_meta["full_remote_path_text"]).decode("utf-8").replace("\\", "/"),
            "size": file_size,
            "object_id": nemesis_id,
        }

    def _check_file_size(self, file_size: int | None) -> bool:
        """Check if a known file size is within the configured Nemesis limit.

        Args:
            file_size: Size of the file in bytes, or None if unknown

        Returns:
            True if the size is unknown or within limits, False if it exceeds max_file_size
        """
        if file_size is None or isinstance(file_size, bool):
            return True
        try:
            return int(file_size) <= self.cfg.nemesis.max_file_size
        except (TypeError, ValueError):
            return True

    def _is_file_processed(self, agent_file_id: str) -> bool:
        """True once a file was uploaded, skipped as too large, or given up on."""
        return (
            self.db.get_strict(f"filemeta{agent_file_id}") is not None
            or self.db.get_strict(self.state_prefix + "failed:" + agent_file_id) is not None
        )

    def _mark_processed(self, agent_file_id: str) -> None:
        cache_key = f"filemeta{agent_file_id}"
        pending_key = self.state_prefix + "pending:" + agent_file_id
        self.db.write_batch({cache_key: "1"}, [pending_key])
        self._pending_changed.set()

    def _mark_failed(self, agent_file_id: str, reason: str) -> None:
        """Permanently stop tracking a file that will never become downloadable."""
        failed_key = self.state_prefix + "failed:" + agent_file_id
        pending_key = self.state_prefix + "pending:" + agent_file_id
        self.db.write_batch({failed_key: json.dumps({"reason": reason, "at": time.time()})}, [pending_key])
        self._pending_changed.set()
        logger.warning("Giving up on Mythic file %s: %s", agent_file_id, reason)

    def _state_value(self, key: str) -> dict[str, Any] | None:
        raw = self.db.get_strict(key)
        return json.loads(raw) if raw else None

    @staticmethod
    def _new_pending_entry(record: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        return {
            "id": record.get("id"),
            "uuid": record["agent_file_id"],
            "attempt": 0,
            "retry_at": 0,
            "progress_at": now,
            "chunks": record.get("chunks_received"),
        }

    def _pending_puts(self, records: list[dict[str, Any]]) -> dict[str, str]:
        puts: dict[str, str] = {}
        for record in records:
            uuid = record.get("agent_file_id")
            if not uuid or record.get("deleted"):
                continue
            if self._is_file_processed(uuid):
                continue
            pending_key = self.state_prefix + "pending:" + str(uuid)
            if self.db.get_strict(pending_key) is None:
                puts[pending_key] = json.dumps(self._new_pending_entry(record))
        return puts

    def _enqueue_discovered(self, records: list[dict[str, Any]], cursor: int) -> None:
        for record in records:
            if type(record.get("id")) is not int:
                raise ValueError("Mythic discovery record is missing an integer ID")
            if not record.get("deleted") and (
                not isinstance(record.get("agent_file_id"), str) or not record["agent_file_id"].strip()
            ):
                raise ValueError("Mythic discovery record is missing its agent file UUID")
        puts: dict[str, str] = {self.state_prefix + "cursor": str(cursor)}
        puts.update(self._pending_puts(records))
        self.db.write_batch(puts)
        if len(puts) > 1:
            self._pending_changed.set()

    async def _refresh_pending(self, pending: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not pending:
            return []
        ids = [entry["id"] for entry in pending if entry.get("id") is not None]
        query = f"""query NemesisMythicPendingFiles($ids:[Int!]!) {{
          filemeta(where:{{id:{{_in:$ids}}}}) {{ {FILE_FIELDS} }}
        }}"""
        result = await mythic.execute_custom_query(mythic=self.mythic, query=query, variables={"ids": ids})
        return result.get("filemeta", [])

    def _pending_entries(self) -> list[tuple[str, dict[str, Any]]]:
        prefix = (self.state_prefix + "pending:").encode()
        try:
            return [(key.decode(), json.loads(value)) for key, value in self.db.db.iterator(prefix=prefix)]
        except Exception as exc:
            raise DatabaseError("LevelDB pending-state iteration failed") from exc

    def _track_progress(self, key: str, entry: dict[str, Any], item: dict[str, Any], now: float) -> None:
        """Record chunk progress of an incomplete download, and give up once it has stalled too long."""
        chunks = item.get("chunks_received")
        if "progress_at" not in entry or chunks != entry.get("chunks"):
            entry.update(progress_at=now, chunks=chunks)
            self.db.write_batch({key: json.dumps(entry)})
            return
        stalled = now - float(entry["progress_at"])
        if stalled >= self.give_up_sec:
            self._mark_failed(
                entry["uuid"],
                f"download incomplete ({chunks}/{item.get('total_chunks')} chunks) "
                f"with no progress for {stalled / 86400:.1f} days",
            )

    async def process_pending_once(self, metadata: list[dict[str, Any]] | None = None) -> None:
        now = time.time()
        deleted = {item["agent_file_id"] for item in metadata or [] if item.get("deleted")}
        due = [
            (key, entry)
            for key, entry in self._pending_entries()
            if entry.get("retry_at", 0) <= now or entry["uuid"] in deleted
        ]
        for offset in range(0, len(due), PENDING_BATCH_SIZE):
            batch = due[offset : offset + PENDING_BATCH_SIZE]
            records = metadata if metadata is not None else await self._refresh_pending([entry for _, entry in batch])
            by_uuid = {item.get("agent_file_id"): item for item in records}
            for key, entry in batch:
                item = by_uuid.get(entry["uuid"])
                if item is None:
                    continue
                if item.get("deleted"):
                    self.db.write_batch({}, [key])
                    self._pending_changed.set()
                    continue
                if not item.get("complete"):
                    self._track_progress(key, entry, item, now)
                    continue
                await self.handle_file(item)
                # handle_file may have finished, failed or updated the entry; build on its stored state.
                current = self._state_value(key)
                if current is None or self._is_file_processed(entry["uuid"]):
                    continue
                attempt = int(current.get("attempt", 0)) + 1
                delay = RETRY_DELAYS_SEC[min(attempt - 1, len(RETRY_DELAYS_SEC) - 1)]
                current.update(attempt=attempt, retry_at=time.time() + delay)
                self.db.write_batch({key: json.dumps(current)})

    async def _discovery_stream(self) -> None:
        raw_cursor = self.db.get_strict(self.state_prefix + "cursor")
        cursor = int(raw_cursor) if raw_cursor else 0
        subscription = f"""subscription NemesisFileSubscription {{
          filemeta_stream(cursor:{{initial_value:{{id:{cursor}}}}},batch_size:100,
            where:{{is_download_from_agent:{{_eq:true}},deleted:{{_eq:false}}}}) {{
            {FILE_FIELDS}
          }}
        }}"""
        async for data in mythic.subscribe_custom_query(mythic=self.mythic, query=subscription, timeout=-1):
            records = data.get("filemeta_stream", [])
            if records:
                newest = max(int(row["id"]) for row in records if row.get("id") is not None)
                self._enqueue_discovered(records, newest)

    async def reconcile_once(self) -> int:
        """Enqueue rows at or just below the cursor that discovery missed; returns how many were added.

        Hasura's stream cursor is ``id > last``. Concurrent inserts can commit out of ID order, so a row with a
        lower ID can become visible after a higher one was streamed. Only IDs and UUIDs are fetched.
        """
        raw_cursor = self.db.get_strict(self.state_prefix + "cursor")
        cursor = int(raw_cursor) if raw_cursor else 0
        if cursor <= 0:
            return 0
        query = """query NemesisMythicReconcile($low:Int!, $high:Int!) {
          filemeta(where:{id:{_gt:$low,_lte:$high},is_download_from_agent:{_eq:true},deleted:{_eq:false}},
                   order_by:{id:asc}) { id agent_file_id chunks_received }
        }"""
        result = await mythic.execute_custom_query(
            mythic=self.mythic,
            query=query,
            variables={"low": max(0, cursor - RECONCILE_ID_WINDOW), "high": cursor},
        )
        records = [
            row
            for row in result.get("filemeta", [])
            if type(row.get("id")) is int and isinstance(row.get("agent_file_id"), str) and row["agent_file_id"]
        ]
        puts = self._pending_puts(records)
        if puts:
            self.db.write_batch(puts)
            self._pending_changed.set()
            logger.info("Reconciliation found %d Mythic file(s) missed by discovery", len(puts))
        return len(puts)

    async def _reconcile_loop(self) -> None:
        while True:
            await asyncio.sleep(RECONCILE_INTERVAL_SEC)
            await self.reconcile_once()

    async def _pending_stream(self, ids: tuple[int, ...]) -> None:
        query = f"""subscription NemesisMythicPendingFiles($ids:[Int!]!) {{
          filemeta(where:{{id:{{_in:$ids}}}}) {{
            {FILE_FIELDS}
          }}
        }}"""
        async for result in mythic.subscribe_custom_query(
            mythic=self.mythic, query=query, variables={"ids": list(ids)}, timeout=-1
        ):
            self._apply_snapshot(ids, result["filemeta"])
        raise TransportClosed("Mythic pending-file subscription ended")

    def _apply_snapshot(self, ids: tuple[int, ...] | list[int], records: list[dict[str, Any]]) -> None:
        for item in records:
            if type(item.get("id")) is not int or item["id"] not in ids or not item.get("agent_file_id"):
                raise ValueError("Invalid Mythic pending-file subscription record")
        # Live queries return full snapshots, including an empty snapshot if
        # rows disappear. Missing rows stay pending rather than being lost.
        for file_id in ids:
            self._pending_metadata.pop(file_id, None)
        self._pending_metadata.update({item["id"]: item for item in records})
        self._metadata_changed.set()

    async def poll_overflow_once(self) -> None:
        """Refresh metadata for pending files that have no live-query subscription."""
        ids = sorted(self._overflow_ids)
        for offset in range(0, len(ids), PENDING_BATCH_SIZE):
            batch = ids[offset : offset + PENDING_BATCH_SIZE]
            records = await self._refresh_pending([{"id": file_id} for file_id in batch])
            self._apply_snapshot(batch, records)

    async def _overflow_poller(self) -> None:
        while True:
            await asyncio.sleep(OVERFLOW_POLL_INTERVAL_SEC)
            if self._overflow_ids:
                await self.poll_overflow_once()

    async def _pending_subscriptions(self) -> None:
        watchers: dict[asyncio.Task, tuple[int, ...]] = {}
        try:
            while True:
                self._pending_changed.clear()
                pending_ids = {entry["id"] for _, entry in self._pending_entries()}
                for task, ids in tuple(watchers.items()):
                    if task.done():
                        task.result()  # Propagate auth, schema and connection failures.
                    if not pending_ids.intersection(ids):
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                        del watchers[task]
                watched_ids = {file_id for ids in watchers.values() for file_id in ids}
                unassigned = pending_ids - watched_ids
                ideal_batches = min(
                    (len(pending_ids) + PENDING_BATCH_SIZE - 1) // PENDING_BATCH_SIZE, self.max_subscriptions
                )
                compact = len(watchers) > 2 * ideal_batches
                # Fill partial batches when discoveries arrive; otherwise a
                # slow sequence of single files could open one socket per file.
                refill = bool(unassigned)
                for task, ids in tuple(watchers.items()):
                    active_ids = pending_ids.intersection(ids)
                    if compact or (refill and len(active_ids) < PENDING_BATCH_SIZE):
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                        del watchers[task]
                        unassigned.update(active_ids)
                new_ids = sorted(unassigned)
                offset = 0
                # Cap open websockets; files beyond the cap are polled by _overflow_poller instead.
                while offset < len(new_ids) and len(watchers) < self.max_subscriptions:
                    ids = tuple(new_ids[offset : offset + PENDING_BATCH_SIZE])
                    offset += PENDING_BATCH_SIZE
                    task = asyncio.create_task(self._pending_stream(ids))
                    task.add_done_callback(lambda _: self._pending_changed.set())
                    watchers[task] = ids
                newly_overflowing = set(new_ids[offset:]) - self._overflow_ids
                self._overflow_ids = set(new_ids[offset:])
                for file_id in tuple(self._pending_metadata):
                    if file_id not in pending_ids:
                        del self._pending_metadata[file_id]
                if newly_overflowing:
                    # Fetch new overflow files right away rather than waiting for the next poll.
                    await self.poll_overflow_once()
                # Keep existing batches stable as files finish, avoiding a full
                # resubscription of the backlog after every successful upload.
                await self._pending_changed.wait()
        finally:
            for task in watchers:
                task.cancel()
            await asyncio.gather(*watchers, return_exceptions=True)

    async def subscribe(self) -> None:
        """Maintain discovery, live pending-file updates and transfer retries."""
        tasks = {
            asyncio.create_task(self._pending_worker()),
            asyncio.create_task(self._pending_subscriptions()),
            asyncio.create_task(self._discovery_stream()),
            asyncio.create_task(self._reconcile_loop()),
            asyncio.create_task(self._overflow_poller()),
        }
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _pending_worker(self) -> None:
        while True:
            self._metadata_changed.clear()
            await self.process_pending_once(list(self._pending_metadata.values()))
            # Only failed transfers need a client-side timer. Unchanged complete
            # records won't produce another live-query message to trigger retry.
            deadlines = [
                entry["retry_at"]
                for _, entry in self._pending_entries()
                if entry.get("retry_at", 0) > 0
                and (item := self._pending_metadata.get(entry["id"]))
                and item.get("complete")
                and not item.get("deleted")
            ]
            # Stalled downloads produce no live-query messages either, so wake periodically to give up on them.
            delay = STALL_CHECK_INTERVAL_SEC
            if deadlines:
                delay = min(delay, max(0, min(deadlines) - time.time()))
            try:
                await asyncio.wait_for(self._metadata_changed.wait(), timeout=delay)
            except TimeoutError:
                pass

    async def download_file(
        self, mythic_file_id: str, download_callback: Callable[[str], Coroutine[Any, Any, Any]]
    ) -> None:
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as temp_file:
                base = f"{self.mythic.http}{self.mythic.server_ip}:{self.mythic.server_port}"
                # No total limit: large files may take far longer than the connect timeout to transfer.
                connect = self.cfg.networking.timeout_sec
                timeout = aiohttp.ClientTimeout(
                    total=None,
                    connect=connect,
                    sock_connect=connect,
                    sock_read=max(DOWNLOAD_READ_TIMEOUT_SEC, connect),
                )
                headers = {}
                if getattr(self.mythic, "apitoken", None):
                    headers["apitoken"] = self.mythic.apitoken
                elif getattr(self.mythic, "access_token", None):
                    headers["Authorization"] = f"Bearer {self.mythic.access_token}"
                async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                    async with session.get(
                        f"{base}/direct/download/{mythic_file_id}",
                        ssl=tls.client_ssl(
                            self.cfg.mythic.url.startswith("https:"),
                            self.cfg.networking.validate_https_certs,
                            getattr(self.cfg.networking, "ca_file", None),
                        ),
                        allow_redirects=False,
                    ) as response:
                        if response.status in (404, 410):
                            raise FileUnavailableError(f"Mythic file no longer exists ({response.status})")
                        if response.status >= 500:
                            raise aiohttp.ClientResponseError(
                                response.request_info,
                                response.history,
                                status=response.status,
                                message="Mythic download server error",
                            )
                        if response.status != 200:
                            raise PermanentMythicError(f"Mythic download rejected ({response.status})")
                        max_size = self.cfg.nemesis.max_file_size
                        if not self._check_file_size(response.content_length):
                            raise FileTooLargeError(
                                f"Mythic file is {response.content_length} bytes (limit {max_size} bytes)"
                            )
                        written = 0
                        async for chunk in response.content.iter_chunked(512_000):
                            written += len(chunk)
                            if not self._check_file_size(written):
                                raise FileTooLargeError(f"Mythic file exceeds limit of {max_size} bytes")
                            temp_file.write(chunk)
                temp_file.flush()

            await download_callback(path)
        finally:
            os.remove(path)

    def _record_missing(self, agent_file_id: str) -> None:
        """Count 404s for a complete, undeleted file; give up after MAX_MISSING_ATTEMPTS (e.g. removed from disk)."""
        key = self.state_prefix + "pending:" + agent_file_id
        entry = self._state_value(key)
        if entry is None:
            return
        missing = int(entry.get("missing", 0)) + 1
        if missing >= MAX_MISSING_ATTEMPTS:
            self._mark_failed(agent_file_id, f"download returned 404 {missing} times although Mythic lists it complete")
            return
        entry["missing"] = missing
        self.db.write_batch({key: json.dumps(entry)})
        logger.warning(
            "Mythic file %s was not available (%d/%d); it will be retried", agent_file_id, missing, MAX_MISSING_ATTEMPTS
        )

    async def handle_file(self, file_meta: dict[str, Any]) -> None:
        """Process a single file download from Mythic.

        This method handles the complete workflow of processing a file:
        1. Checks if the file has already been processed
        2. Validates the file size
        3. Downloads the file from Mythic
        4. Uploads the file to Nemesis
        5. Creates and uploads the associated metadata
        6. Updates the processing state in the database

        Args:
            file_meta: File metadata from Mythic
        """
        try:
            agent_file_id = file_meta["agent_file_id"]
            file_id = file_meta["id"]
            file_name = _decode_text(file_meta.get("filename_text"))
            path = _remote_path(file_meta, file_name, _decode_text(file_meta.get("full_remote_path_text")))

            logger.debug(f"Processing file. ID: {file_id}. Name: {file_name}. Agent ID: {agent_file_id}")

            if self._is_file_processed(agent_file_id):
                logger.debug(f"File {agent_file_id} already processed, skipping")
                return

            # Size is enforced during the download (Content-Length and streamed bytes): Mythic's filemeta
            # has no size column readable over GraphQL.

            # Download and process file
            # file_bytes = await mythic.download_file(mythic=self.mythic, file_uuid=agent_file_id)

            async def upload_to_nemesis(file_path: str) -> None:
                """Callback to upload the downloaded file to Nemesis."""

                self._total_files_count += 1
                # Use the host field as the source identifier
                source = f"host://{file_meta.get('host', 'unknown')}"

                timestamp, expiration = collection_times(
                    _parse_mythic_timestamp(file_meta.get("timestamp")), self.cfg.nemesis.expiration_days
                )
                metadata = FileMetadata(
                    agent_id=self.cfg.mythic.agent_id,
                    source=source,
                    project=self.cfg.project,
                    timestamp=timestamp,
                    expiration=expiration,
                    path=str(path),
                )

                response = await self.nemesis.post_file(file_path, metadata)

                if isinstance(response, (FileWithMetadataResponse, PreviewUploadResult)):
                    self._mark_processed(agent_file_id)
                    self._successful_files_count += 1
                    if isinstance(response, PreviewUploadResult):
                        logger.info(
                            "Dry run previewed Mythic file %s: %d bytes sha256=%s",
                            agent_file_id,
                            response.size_bytes,
                            response.sha256,
                        )
                    else:
                        logger.info(
                            f"Successfully processed file {agent_file_id} (Nemesis ID: {response.object_id}) - {self._successful_files_count}/{self._total_files_count} files processed"
                        )

                elif response is None:
                    logger.warning("Upload failed: No response from server")
                else:
                    logger.error(f"Upload failed: {response.detail}")

            await self.download_file(agent_file_id, upload_to_nemesis)

        except asyncio.CancelledError:
            raise
        except (DatabaseError, PermanentMythicError):
            raise
        except FileTooLargeError as e:
            logger.warning(f"Skipping uploading file '{file_name}' (UUID: {agent_file_id}): {e}")
            self._mark_processed(agent_file_id)
        except FileUnavailableError:
            refreshed = await self._refresh_pending([{"id": file_id, "uuid": agent_file_id}])
            if any(row.get("agent_file_id") == agent_file_id and row.get("deleted") for row in refreshed):
                self.db.write_batch({}, [self.state_prefix + "pending:" + agent_file_id])
                self._pending_changed.set()
                logger.info("Discarded deleted Mythic file %s after download returned missing", agent_file_id)
            elif file_meta.get("complete"):
                self._record_missing(agent_file_id)
            else:
                logger.warning("Mythic file %s was not available; metadata will be retried", agent_file_id)
        except Exception as e:
            logger.exception(f"Error processing file {file_meta.get('id')}: {str(e)}")


# class FileBrowserHandler:
#     """Handles synchronization of file browser data from Mythic to Nemesis.

#     This class manages the processing of file system information that Mythic agents
#     collect, including directory listings and file metadata. It batches related
#     information by agent ID to minimize API calls to Nemesis.
#     """

#     def __init__(self, mythic: mythic_classes.Mythic, nemesis: UploadClient, db: Database, config: Settings):
#         """Initialize the file browser handler.

#         Args:
#             mythic: Authenticated Mythic client instance
#             nemesis: Nemesis API client
#             db: Database connection
#             config: Application configuration
#         """
#         self.mythic = mythic
#         self.nemesis = nemesis
#         self.db = db
#         self.config = config

#     def _convert_timestamp(self, timestamp: str, days_to_add: int = 0) -> str:
#         """Convert timestamp to a standard format.

#         Args:
#             timestamp: Input timestamp string
#             days_to_add: Optional number of days to add

#         Returns:
#             Formatted timestamp string
#         """
#         dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")
#         if days_to_add:
#             dt += timedelta(days=days_to_add)
#         return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

#     def _convert_epoch_timestamp(self, epoch_ms: int) -> str:
#         """Convert epoch milliseconds to standard timestamp format.

#         Args:
#             epoch_ms: Timestamp in milliseconds since epoch

#         Returns:
#             Formatted timestamp string
#         """
#         return datetime.fromtimestamp(epoch_ms // 1000).strftime("%Y-%m-%dT%H:%M:%S.000Z")

#     def _build_metadata(self, file_data: dict[str, Any]) -> dict[str, Any]:
#         """Build metadata dictionary for Nemesis.

#         Args:
#             file_data: File system data from Mythic

#         Returns:
#             Formatted metadata dictionary
#         """
#         return {
#             "agent_id": file_data["task"]["callback"]["agent_callback_id"],
#             "agent_type": "mythic",
#             "automated": True,
#             "data_type": "file_information",
#             "expiration": self._convert_timestamp(file_data["timestamp"], self.config.nemesis.expiration_days),
#             "source": file_data["host"],
#             "project": file_data["task"]["callback"]["operation"]["name"],
#             "timestamp": self._convert_timestamp(file_data["timestamp"]),
#         }

#     def _build_file_data(self, file_data: dict[str, Any]) -> dict[str, Any]:
#         """Build file information dictionary for Nemesis.

#         Args:
#             file_data: File system data from Mythic

#         Returns:
#             Formatted file information dictionary
#         """
#         result = {
#             "path": file_data["full_path_text"].replace("\\", "/"),
#             "type": "folder" if file_data.get("can_have_children") else "file",
#         }

#         metadata = file_data.get("metadata", {})

#         # Add file size if available
#         if "size" in metadata:
#             result["size"] = metadata["size"]

#         # Handle timestamps
#         if "access_time" in metadata and metadata["access_time"]:
#             access_time = metadata["access_time"]
#             if isinstance(access_time, int):
#                 result["access_time"] = self._convert_epoch_timestamp(access_time)
#             else:
#                 result["access_time"] = self._convert_timestamp(access_time)

#         if "modify_time" in metadata and metadata["modify_time"]:
#             modify_time = metadata["modify_time"]
#             if isinstance(modify_time, int):
#                 result["modification_time"] = self._convert_epoch_timestamp(modify_time)
#             else:
#                 result["modification_time"] = self._convert_timestamp(modify_time)

#         # Handle Unix-style permissions
#         if (
#             "permissions" in metadata
#             and metadata["permissions"]
#             and len(metadata["permissions"]) > 0
#             and "permissions" in metadata["permissions"][0]
#             and metadata["permissions"][0]["permissions"]
#         ):
#             try:
#                 permission_data = json.loads(metadata["permissions"][0]["permissions"])
#                 if "user" in permission_data:
#                     result["owner"] = permission_data["user"]
#             except json.JSONDecodeError:
#                 logger.warning(f"Failed to parse permissions for {result['path']}")

#         return result

#     async def handle_batch(self, files: list[dict[str, Any]]) -> None:
#         """Process a batch of file system information.

#         This method groups file information by agent ID to minimize API calls
#         while maintaining data consistency.

#         Args:
#             files: List of file system entries from Mythic
#         """
#         # Group data by agent ID
#         grouped_data: dict[str, dict[str, Any]] = {}

#         for file_data in files:
#             mythic_id = file_data["id"]
#             cache_key = f"filebrowser{mythic_id}"

#             # Skip if already processed
#             if self.db.get(cache_key):
#                 continue

#             callback_id = file_data["task"]["callback"]["agent_callback_id"]

#             # Initialize group for new agent ID
#             if callback_id not in grouped_data:
#                 grouped_data[callback_id] = {"metadata": self._build_metadata(file_data), "data": []}

#             # Add file information to group
#             grouped_data[callback_id]["data"].append(self._build_file_data(file_data))

#             # Mark as processed and update last ID
#             self.db.mset({cache_key: 1})
#             last_id = self.db.get("last_filebrowser_id")
#             if last_id is None or mythic_id > last_id:
#                 self.db.mset({"last_filebrowser_id": mythic_id})

#         # Submit each group to Nemesis
#         for data in grouped_data.values():
#             resp = self.nemesis.post_data(data)
#             if resp:
#                 message_id = resp["object_id"]
#                 logger.info(f"Nemesis message_id for file listing data: {message_id}")

#     async def subscribe(self) -> None:
#         """Subscribe to file browser information from Mythic."""
#         try:
#             start_id = self.db.get("last_filebrowser_id") or 0
#         except Exception:
#             self.db.mset({"last_filebrowser_id": 0})
#             start_id = 0

#         subscription = (
#             """
#         subscription NemesisFileBrowserSubscription {
#             mythictree_stream(
#                 batch_size: 100,
#                 cursor: {initial_value: {id: %s}},
#                 where: {tree_type: {_eq: "file"}}
#             ) {
#                 id
#                 host
#                 full_path_text
#                 name_text
#                 parent_path_text
#                 timestamp
#                 can_have_children
#                 task {
#                     callback {
#                         agent_callback_id
#                         operation {
#                             name
#                         }
#                     }
#                     id
#                 }
#                 metadata
#             }
#         }
#         """  # noqa: UP031
#             % start_id
#         )

#         logger.info(f"Starting subscription for file browser information, start_id: {start_id}")

#         async for data in mythic.subscribe_custom_query(mythic=self.mythic, query=subscription):
#             await self.handle_batch(data["mythictree_stream"])
