"""Small, stateful Mythic HTTP/GraphQL/WebSocket test surrogate.

This intentionally models only the protocol used by this CLI. It is not a
replacement for a real Mythic or Hasura deployment.
"""

import asyncio
import base64
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from aiohttp import WSMsgType, web


@dataclass
class SurrogateFile:
    id: int
    data: bytes
    name: str = "report.txt"
    path: str = "/tmp/report.txt"
    host: str = "agent01"
    agent_file_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    complete: bool = True
    deleted: bool = False
    download_mode: str = "normal"  # normal, missing, html, truncated

    def metadata(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "agent_file_id": self.agent_file_id,
            "deleted": self.deleted,
            "complete": self.complete,
            "filename_text": base64.b64encode(self.name.encode()).decode(),
            "full_remote_path_text": base64.b64encode(self.path.encode()).decode(),
            "host": self.host,
            "timestamp": "2025-01-01T00:00:00.000000",
            "is_download_from_agent": True,
            "task": {"callback": {"agent_callback_id": "callback-1", "operation": {"name": "test"}}, "id": 1},
            "tags": [],
        }


class MythicSurrogate:
    def __init__(self) -> None:
        self.files: dict[str, SurrogateFile] = {}
        self.valid_username = "operator"
        self.valid_password = "password"
        self.token = "surrogate-api-token"
        self.token_valid = True
        self.auth_valid = True
        self.filemeta_denied = False
        self.ws_disconnect = False
        self.event_log: list[dict[str, Any]] = []
        self.download_started: asyncio.Event | None = None
        self.download_release: asyncio.Event | None = None
        self._ws: dict[web.WebSocketResponse, dict[str, Any]] = {}
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self.port: int | None = None
        self._bound_port: int | None = None
        self.app = web.Application()
        self.app.router.add_get("/", self.root)
        self.app.router.add_post("/auth", self.auth)
        self.app.router.add_post("/graphql/", self.graphql)
        self.app.router.add_get("/graphql/", self.websocket)
        self.app.router.add_get("/direct/download/{file_id}", self.download)

    @property
    def url(self) -> str:
        assert self.port is not None
        return f"http://127.0.0.1:{self.port}"

    async def start(self) -> "MythicSurrogate":
        self._runner = web.AppRunner(self.app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", self._bound_port or 0)
        await self._site.start()
        assert self._site._server and self._site._server.sockets
        self.port = self._site._server.sockets[0].getsockname()[1]
        self._bound_port = self.port
        return self

    async def close(self) -> None:
        for ws in tuple(self._ws):
            await ws.close()
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self.port = None

    def add_file(self, data: bytes, **kwargs: Any) -> SurrogateFile:
        row = SurrogateFile(id=max((f.id for f in self.files.values()), default=0) + 1, data=data, **kwargs)
        self.files[row.agent_file_id] = row
        self.event_log.append({"event": "file_added", "id": row.id, "complete": row.complete})
        return row

    async def root(self, _request: web.Request) -> web.Response:
        return web.Response(text="Mythic surrogate")

    async def auth(self, request: web.Request) -> web.Response:
        body = await request.json()
        valid = (
            self.auth_valid
            and body.get("username") == self.valid_username
            and body.get("password") == self.valid_password
        )
        self.event_log.append({"event": "auth", "valid": valid})
        if not valid:
            return web.json_response({"error": "invalid username or password"}, status=401)
        return web.json_response(
            {"access_token": "surrogate-jwt", "refresh_token": "surrogate-refresh", "user": {"current_operation_id": 1}}
        )

    def _authorized(self, request: web.Request) -> bool:
        bearer = request.headers.get("Authorization", "")
        return (self.token_valid and request.headers.get("apitoken") == self.token) or (
            self.auth_valid and bearer == "Bearer surrogate-jwt"
        )

    async def restart(self) -> None:
        """Bring the server back on its original loopback port after an outage."""
        await self.close()
        await self.start()

    async def disconnect_websockets(self) -> None:
        for ws in tuple(self._ws):
            await ws.close()

    async def complete_subscriptions(self) -> None:
        for ws, state in tuple(self._ws.items()):
            if state["op_id"]:
                await ws.send_json({"type": "complete", "id": state["op_id"]})
                self.event_log.append({"event": "ws_complete", "id": state["op_id"]})
                await ws.close()

    async def graphql(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return web.json_response({"errors": [{"message": "permission denied: invalid API token"}]}, status=200)
        body = await request.json()
        op = body.get("operationName", "")
        query = body.get("query", "")
        result: dict[str, Any]
        if self.filemeta_denied and "filemeta" in query:
            self.event_log.append({"event": "filemeta_denied", "operation": op})
            return web.json_response({"errors": [{"message": "permission denied for filemeta"}]})
        if "apitokens" in query:
            result = {"apitokens": [{"token_value": self.token, "active": True, "id": 1}]}
        elif "createAPIToken" in query:
            result = {"createAPIToken": {"status": "success", "token_value": self.token, "error": ""}}
        elif "meHook" in query:
            result = {
                "meHook": {
                    "status": "success",
                    "error": "",
                    "current_operation_id": 1,
                    "current_operation": {"id": 1, "name": "test"},
                },
                "filemeta": [{"id": 1}] if self.files else [],
            }
        elif "filemeta" in query:
            ids = body.get("variables", {}).get("ids", [])
            rows = [f.metadata() for f in self.files.values() if not ids or f.id in ids or f.agent_file_id in ids]
            result = {"filemeta": rows}
        else:
            result = {}
        self.event_log.append({"event": "graphql", "operation": op})
        return web.json_response({"data": result})

    async def websocket(self, request: web.Request) -> web.StreamResponse:
        if not self._authorized(request):
            return web.Response(status=401, text="invalid API token")
        ws = web.WebSocketResponse(protocols=("graphql-ws",))
        await ws.prepare(request)
        self._ws[ws] = {"cursor": 0, "complete_only": False, "op_id": None}
        self.event_log.append({"event": "ws_open"})
        try:
            async for message in ws:
                if message.type != WSMsgType.TEXT:
                    continue
                payload = json.loads(message.data)
                if payload.get("type") == "connection_init":
                    await ws.send_json({"type": "connection_ack"})
                elif payload.get("type") == "start":
                    op_id = payload.get("id", "1")
                    query = payload.get("payload", {}).get("query", "")
                    await self._send_snapshot(ws, op_id, query)
                    self.event_log.append({"event": "ws_start", "id": op_id})
                    if self.ws_disconnect:
                        await ws.close()
                        break
                    # Keep the subscription live; add_file/complete_file can publish later.
                    self._ws[ws]["op_id"] = op_id
                    self.event_log.append({"event": "ws_ready", "id": op_id})
                elif payload.get("type") == "stop":
                    await ws.send_json({"type": "complete", "id": payload.get("id", "1")})
        finally:
            self._ws.pop(ws, None)
            self.event_log.append({"event": "ws_close"})
        return ws

    async def _send_snapshot(self, ws: web.WebSocketResponse, op_id: str, query: str) -> None:
        # Cursor semantics match Hasura: return rows strictly greater than id.
        import re

        match = re.search(r"id\s*:\s*(\d+)", query)
        cursor = int(match.group(1)) if match else 0
        complete_only = "complete:{_eq:true}" in query.replace(" ", "")
        self._ws[ws].update(cursor=cursor, complete_only=complete_only)
        rows = [
            f.metadata()
            for f in self.files.values()
            if f.id > cursor and not f.deleted and (not complete_only or f.complete)
        ]
        if rows:
            await ws.send_json({"type": "data", "id": op_id, "payload": {"data": {"filemeta_stream": rows}}})
            self._ws[ws]["cursor"] = max(int(row["id"]) for row in rows)
            self.event_log.append({"event": "ws_data", "ids": [row["id"] for row in rows]})

    async def publish(self, row: SurrogateFile) -> None:
        for ws, state in tuple(self._ws.items()):
            op_id = state["op_id"]
            if (
                op_id
                and not ws.closed
                and not row.deleted
                and row.id > state["cursor"]
                and (not state["complete_only"] or row.complete)
            ):
                await ws.send_json(
                    {"type": "data", "id": op_id, "payload": {"data": {"filemeta_stream": [row.metadata()]}}}
                )
                state["cursor"] = row.id
                self.event_log.append({"event": "ws_data", "ids": [row.id]})

    async def complete_file(self, row: SurrogateFile) -> None:
        row.complete = True
        self.event_log.append({"event": "file_completed", "id": row.id})
        await self.publish(row)

    async def download(self, request: web.Request) -> web.StreamResponse:
        row = self.files.get(request.match_info["file_id"])
        self.event_log.append({"event": "download", "id": row.id if row else None})
        if self.download_started is not None and self.download_release is not None:
            self.download_started.set()
            await self.download_release.wait()
        if row is None or row.deleted or not row.complete or row.download_mode == "missing":
            return web.Response(status=404, text="not found")
        if row.download_mode == "html":
            return web.Response(status=403, text="<html>login required</html>", content_type="text/html")
        response = web.StreamResponse(status=200, headers={"Content-Type": "application/octet-stream"})
        if row.download_mode == "truncated":
            response.headers["Content-Length"] = str(len(row.data))
        await response.prepare(request)
        if row.download_mode == "truncated":
            await response.write(row.data[: max(1, len(row.data) // 2)])
            request.transport.close()
            return response
        await response.write(row.data)
        await response.write_eof()
        return response


async def _serve_forever() -> None:
    server = await MythicSurrogate().start()
    sample = server.add_file(
        b"Nemesis CLI dry-run sample evidence\n",
        name="dry-run-sample.txt",
        path="C:\\Users\\operator\\Desktop\\dry-run-sample.txt",
    )
    print(f"Mythic protocol surrogate listening at {server.url}; test file {sample.agent_file_id}")
    try:
        await asyncio.Event().wait()
    finally:
        await server.close()


if __name__ == "__main__":
    asyncio.run(_serve_forever())
