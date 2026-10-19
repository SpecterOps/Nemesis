"""Loopback HTTP endpoint for exercising real CLI uploads."""

import hashlib
import json
import uuid
from typing import Any

from aiohttp import web


class NemesisSurrogate:
    def __init__(self) -> None:
        self.online = True
        self.fail_status: int | None = None
        self.drop_accepted_response = False
        self.uploads: list[dict[str, Any]] = []
        self._runner: web.AppRunner | None = None
        self.port: int | None = None
        self.app = web.Application()
        self.app.router.add_get("/api/system/health", self.health)
        self.app.router.add_post("/api/files", self.upload)

    @property
    def url(self) -> str:
        assert self.port is not None
        return f"http://127.0.0.1:{self.port}"

    async def start(self) -> "NemesisSurrogate":
        self._runner = web.AppRunner(self.app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        assert site._server and site._server.sockets
        self.port = site._server.sockets[0].getsockname()[1]
        self._site = site
        return self

    async def close(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self.port = None

    async def health(self, _request: web.Request) -> web.Response:
        return web.json_response({"status": "healthy"}) if self.online else web.Response(status=503, text="offline")

    async def upload(self, request: web.Request) -> web.Response:
        if not self.online:
            return web.Response(status=503, text="offline")
        if self.fail_status:
            return web.Response(status=self.fail_status, text="injected failure")
        reader = await request.multipart()
        fields: dict[str, Any] = {}
        file_bytes = b""
        async for part in reader:
            if part.name in {"file", "data"}:
                file_bytes = await part.read(decode=False)
                fields["filename"] = part.filename
            else:
                raw = await part.text()
                try:
                    fields[part.name] = json.loads(raw)
                except json.JSONDecodeError:
                    fields[part.name] = raw
        upload = {"bytes": file_bytes, "sha256": hashlib.sha256(file_bytes).hexdigest(), "metadata": fields}
        self.uploads.append(upload)
        if self.drop_accepted_response:
            request.transport.close()
            return web.Response()
        return web.json_response({"object_id": str(uuid.uuid4()), "submission_id": str(uuid.uuid4())}, status=200)
