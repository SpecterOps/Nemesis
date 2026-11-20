"""Tests for the cross-site request blocker (CSRF protection for the API behind basic auth)."""

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from web_api.cross_site import CrossSiteRequestBlocker, is_cross_site_request


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(CrossSiteRequestBlocker)
    calls = []

    @app.post("/files")
    async def upload():
        calls.append("upload")
        return {"ok": True}

    @app.get("/reports/system/pdf")
    async def report():
        calls.append("report")
        return {"ok": True}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("hi")
        await websocket.close()

    app.state.calls = calls
    return app


@pytest.fixture
def client():
    app = _app()
    with TestClient(app, base_url="https://nemesis.example:7443") as c:
        c.calls = app.state.calls
        yield c


def _scope(**headers):
    return {"type": "http", "headers": [(k.replace("_", "-").encode(), v.encode()) for k, v in headers.items()]}


# --- allowed -------------------------------------------------------------------------------------


def test_api_clients_without_browser_headers_are_allowed(client):
    # CLI, C2 connectors, Jupyter, Dapr, health checks: no Sec-Fetch-Site / Origin
    assert client.post("/files").status_code == 200
    assert client.get("/reports/system/pdf").status_code == 200
    assert client.calls == ["upload", "report"]


@pytest.mark.parametrize("site", ["same-origin", "none", "SAME-ORIGIN"])
def test_requests_from_the_nemesis_ui_or_typed_urls_are_allowed(client, site):
    assert client.post("/files", headers={"Sec-Fetch-Site": site}).status_code == 200


def test_same_origin_by_origin_header_is_allowed(client):
    # Older browser without Sec-Fetch-*: Origin matches the host the request went to
    headers = {"Origin": "https://nemesis.example:7443"}
    assert client.post("/files", headers=headers).status_code == 200


def test_origin_matches_forwarded_host_behind_the_proxy(client):
    headers = {
        "Origin": "https://nemesis.example:7443",
        "Host": "web-api:8000",
        "X-Forwarded-Host": "nemesis.example:7443",
    }
    assert client.post("/files", headers=headers).status_code == 200


def test_websocket_from_the_ui_is_allowed(client):
    headers = {"Origin": "https://nemesis.example:7443", "Host": "nemesis.example:7443", "X-Forwarded-Proto": "https"}
    with client.websocket_connect("/ws", headers=headers) as ws:
        assert ws.receive_text() == "hi"


# --- blocked -------------------------------------------------------------------------------------


@pytest.mark.parametrize("site", ["cross-site", "same-site", " Cross-Site "])
def test_cross_site_form_upload_is_rejected_and_never_reaches_the_route(client, site):
    resp = client.post("/files", headers={"Sec-Fetch-Site": site}, data={"metadata": "{}"})
    assert resp.status_code == 403
    assert resp.json() == {"detail": "Cross-site requests to the Nemesis API are not allowed"}
    assert client.calls == []


def test_cross_site_navigation_to_the_report_is_rejected(client):
    # Exploit 4: a link on another site starting a report render with the operator's login
    headers = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}
    assert client.get("/reports/system/pdf", headers=headers).status_code == 403
    assert client.calls == []


def test_foreign_origin_without_sec_fetch_is_rejected(client):
    assert client.post("/files", headers={"Origin": "https://attacker.example"}).status_code == 403
    # Same host name on another port or scheme is another origin too
    assert client.post("/files", headers={"Origin": "http://nemesis.example:7443"}).status_code == 403
    assert client.post("/files", headers={"Origin": "https://nemesis.example:8443"}).status_code == 403
    assert client.calls == []


def test_opaque_null_origin_is_rejected(client):
    assert client.post("/files", headers={"Origin": "null"}).status_code == 403


def test_sec_fetch_site_wins_over_a_matching_origin(client):
    headers = {"Sec-Fetch-Site": "cross-site", "Origin": "https://nemesis.example:7443"}
    assert client.post("/files", headers=headers).status_code == 403


def test_cross_site_websocket_is_refused(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws", headers={"Origin": "https://attacker.example"}) as ws:
            ws.receive_text()
    assert exc.value.code == 1008


# --- the decision function on its own ------------------------------------------------------------


def test_is_cross_site_request_edge_cases():
    assert is_cross_site_request(_scope()) is False
    assert is_cross_site_request(_scope(origin="http://a.example", host="a.example")) is False
    assert (
        is_cross_site_request(_scope(origin="https://A.Example", host="a.example", x_forwarded_proto="https")) is False
    )
    # Same host, different scheme: an http:// page is not the https:// site
    assert is_cross_site_request(_scope(origin="http://a.example", host="a.example", x_forwarded_proto="https")) is True
    assert is_cross_site_request(_scope(origin="https://a.example", host="b.example")) is True
    # A comma-separated X-Forwarded-Host (proxy chain) uses the first, client-facing host
    assert (
        is_cross_site_request(
            _scope(origin="https://a.example", x_forwarded_host="a.example, inner:80", x_forwarded_proto="https, http")
        )
        is False
    )
    # No Host at all but a browser Origin: treat as foreign
    assert is_cross_site_request(_scope(origin="https://a.example")) is True
