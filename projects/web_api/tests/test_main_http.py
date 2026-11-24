"""Tests for the async upstream HTTP calls, enrichment-name validation, timeout middleware and
synthesis date filters in web_api.main (#165, #72, #171, #170)."""

import asyncio
import functools
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import web_api.main as main
import web_api.reporting_routes as reporting_routes
from fastapi import Request


def _response(status_code=200, json_body=None, text=None) -> httpx.Response:
    if json_body is not None:
        return httpx.Response(status_code, json=json_body)
    return httpx.Response(status_code, text=text or "")


@pytest.fixture
def http_mock(monkeypatch):
    mock = AsyncMock(return_value=_response(json_body={}))
    monkeypatch.setattr(main, "_http_request", mock)
    return mock


class TestHttpRequestHelper:
    def test_sends_request_with_timeout(self, monkeypatch):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["body"] = json.loads(request.content)
            captured["timeout"] = request.extensions["timeout"]
            return httpx.Response(200, json={"ok": True})

        monkeypatch.setattr(
            main.httpx, "AsyncClient", functools.partial(httpx.AsyncClient, transport=httpx.MockTransport(handler))
        )
        response = asyncio.run(main._http_request("POST", "http://dapr/x", json_body={"a": 1}, timeout=12))
        assert response.json() == {"ok": True}
        assert captured["method"] == "POST"
        assert captured["body"] == {"a": 1}
        assert captured["timeout"]["read"] == 12
        assert captured["timeout"]["connect"] == main.DAPR_CONNECT_TIMEOUT

    def test_timeout_propagates(self, monkeypatch):
        def handler(request):
            raise httpx.ReadTimeout("slow", request=request)

        monkeypatch.setattr(
            main.httpx, "AsyncClient", functools.partial(httpx.AsyncClient, transport=httpx.MockTransport(handler))
        )
        with pytest.raises(httpx.TimeoutException):
            asyncio.run(main._http_request("GET", "http://dapr/x", timeout=1))


class TestListEnrichments:
    def test_returns_upstream_json_with_timeout(self, client, http_mock):
        http_mock.return_value = _response(json_body={"modules": ["yara"]})
        response = client.get("/enrichments")
        assert response.status_code == 200
        assert response.json() == {"modules": ["yara"]}
        assert http_mock.await_args.kwargs["timeout"] == 30

    def test_connection_error_returns_503(self, client, http_mock):
        http_mock.side_effect = httpx.ConnectError("refused")
        assert client.get("/enrichments").status_code == 503

    def test_upstream_error_status_is_passed_through(self, client, http_mock):
        http_mock.return_value = _response(502, text="bad gateway")
        assert client.get("/enrichments").status_code == 502


class TestRunEnrichment:
    @pytest.mark.parametrize("name", ["..", "Yara", "a-b", "a.b", "%2e%2e", "yara%2F..", ""])
    def test_invalid_names_rejected_before_any_call(self, client, http_mock, mock_storage, name):
        response = client.post(f"/enrichments/{name}", json={"object_id": "abc"})
        assert response.status_code in (400, 404, 405)
        http_mock.assert_not_called()
        mock_storage.check_file_exists.assert_not_called()

    def test_dotdot_returns_400(self, client, http_mock):
        # Starlette doesn't normalize an encoded "..", so it reaches the route and must be rejected there
        response = client.post("/enrichments/%2E%2E", json={"object_id": "abc"})
        assert response.status_code == 400
        http_mock.assert_not_called()

    def test_valid_name_forwards(self, client, http_mock, mock_storage):
        http_mock.return_value = _response(
            json_body={"status": "ok", "message": "m", "instance_id": "i", "object_id": "abc"}
        )
        response = client.post("/enrichments/yara_scanner2", json={"object_id": "abc"})
        assert response.status_code == 200
        method, url = http_mock.await_args.args
        assert method == "POST"
        assert url.endswith("/method/enrichments/yara_scanner2")
        assert http_mock.await_args.kwargs["json_body"] == {"object_id": "abc"}

    def test_timeout_returns_504(self, client, http_mock, mock_storage):
        http_mock.side_effect = httpx.ReadTimeout("slow")
        assert client.post("/enrichments/yara", json={"object_id": "abc"}).status_code == 504

    def test_missing_file_returns_404(self, client, http_mock, mock_storage):
        mock_storage.check_file_exists.return_value = False
        assert client.post("/enrichments/yara", json={"object_id": "abc"}).status_code == 404
        http_mock.assert_not_called()

    def test_validate_enrichment_name_helper(self):
        main.validate_enrichment_name("good_name_1")
        with pytest.raises(main.HTTPException) as exc:
            main.validate_enrichment_name("../x")
        assert exc.value.status_code == 400


class TestAgentRoutes:
    def test_agents_list_uses_async_metadata(self, client, http_mock):
        http_mock.return_value = _response(json_body={"agents": [{"name": "a"}]})
        response = client.get("/agents")
        assert response.json()["total_count"] == 1

    def test_agents_list_timeout_returns_empty(self, client, http_mock):
        http_mock.side_effect = httpx.ReadTimeout("slow")
        response = client.get("/agents")
        assert response.status_code == 200
        assert response.json()["agents"] == []

    def test_spend_data_bad_json_returns_defaults(self, client, http_mock):
        http_mock.return_value = _response(200, text="not json")
        response = client.get("/agents/spend-data")
        assert response.status_code == 200
        assert response.json()["total_spend"] == 0.0

    def test_text_summarizer_timeout_returns_504(self, client, http_mock):
        http_mock.side_effect = httpx.ConnectTimeout("slow")
        assert client.post("/agents/text_summarizer", json={"object_id": "x"}).status_code == 504

    def test_translate_connect_error_returns_503(self, client, http_mock):
        http_mock.side_effect = httpx.ConnectError("refused")
        assert client.post("/agents/translate", json={"object_id": "x"}).status_code == 503


class TestAvailableServices:
    def test_traefik_error_status_falls_back(self, client, http_mock):
        http_mock.return_value = httpx.Response(500, request=httpx.Request("GET", "http://traefik"))
        response = client.get("/system/available-services")
        assert response.json()["source"] == "fallback"

    def test_traefik_routers_parsed(self, client, http_mock):
        http_mock.return_value = httpx.Response(
            200, json=[{"name": "grafana@docker", "status": "enabled"}], request=httpx.Request("GET", "http://t")
        )
        response = client.get("/system/available-services")
        assert response.json() == {"available": True, "services": ["/grafana"], "source": "traefik"}


class TestTimeoutMiddleware:
    def test_timeout_returns_504_json(self):
        async def call_next(request):
            raise TimeoutError

        request = Request({"type": "http", "path": "/workflows/status", "headers": [], "query_string": b""})
        response = asyncio.run(main.timeout_middleware(request, call_next))
        assert response.status_code == 504
        assert json.loads(response.body) == {"detail": "Request timeout"}

    def test_passes_through_response(self):
        sentinel = MagicMock()

        async def call_next(request):
            return sentinel

        request = Request({"type": "http", "path": "/files", "headers": [], "query_string": b""})
        assert asyncio.run(main.timeout_middleware(request, call_next)) is sentinel


class TestSourceSynthesisDateFilters:
    def test_date_filters_passed_to_report(self, client, http_mock, monkeypatch):
        report = MagicMock()
        report.model_dump.return_value = {}
        get_report = MagicMock(return_value=report)
        monkeypatch.setattr(reporting_routes, "get_source_report_data", get_report)
        monkeypatch.setattr(main, "get_db_pool", lambda: "pool")
        http_mock.return_value = _response(json_body={"success": True, "full_report_markdown": "x"})

        response = client.post(
            "/reports/source/synthesize",
            params={"source": "host://a", "start_date": "2026-01-01T00:00:00Z", "end_date": "2026-02-01T00:00:00Z"},
        )
        assert response.status_code == 200
        _, source, start, end = get_report.call_args.args
        assert source == "host://a"
        assert start.isoformat().startswith("2026-01-01")
        assert end.isoformat().startswith("2026-02-01")
        assert http_mock.await_args.kwargs["timeout"] == 120

    def test_no_dates_defaults_to_none(self, client, http_mock, monkeypatch):
        report = MagicMock()
        report.model_dump.return_value = {}
        get_report = MagicMock(return_value=report)
        monkeypatch.setattr(reporting_routes, "get_source_report_data", get_report)
        monkeypatch.setattr(main, "get_db_pool", lambda: "pool")
        http_mock.return_value = _response(500, text="err")

        response = client.post("/reports/source/synthesize", params={"source": "s"})
        assert response.status_code == 503
        assert get_report.call_args.args[2:] == (None, None)


def _completion_event(data: dict) -> dict:
    return {
        "data": data,
        "datacontenttype": "application/json",
        "id": "1",
        "pubsubname": main.WORKFLOW_MONITOR_PUBSUB,
        "source": "test",
        "specversion": "1.0",
        "topic": main.WORKFLOW_MONITOR_COMPLETED_TOPIC,
        "traceid": "",
        "traceparent": "",
        "tracestate": "",
        "type": "com.dapr.event.sent",
    }


COMPLETION_ROUTE = f"/events/{main.WORKFLOW_MONITOR_PUBSUB}/{main.WORKFLOW_MONITOR_COMPLETED_TOPIC}"


class TestWorkflowCompletion:
    def test_updates_progress_and_cleans_up(self, client, monkeypatch):
        update = MagicMock(return_value=True)
        cleanup = MagicMock()
        monkeypatch.setattr(main.container_processor, "update_container_workflow_progress", update)
        monkeypatch.setattr(main.container_processor.progress_tracker, "cleanup", cleanup)
        data = {"object_id": "o", "originating_container_id": "c", "completed": True, "file_size": 5}

        response = client.post(COMPLETION_ROUTE, json=_completion_event(data))
        assert response.status_code == 200
        update.assert_called_once_with("c", file_size=5, increment_completed=True, increment_failed=False)
        cleanup.assert_any_call("c")

    def test_missing_fields_skips_update(self, client, monkeypatch):
        update = MagicMock()
        monkeypatch.setattr(main.container_processor, "update_container_workflow_progress", update)
        response = client.post(COMPLETION_ROUTE, json=_completion_event({"object_id": "o"}))
        assert response.status_code == 200
        update.assert_not_called()

    def test_db_error_is_swallowed(self, client, monkeypatch):
        update = MagicMock(side_effect=RuntimeError("db down"))
        monkeypatch.setattr(main.container_processor, "update_container_workflow_progress", update)
        data = {"object_id": "o", "originating_container_id": "c", "completed": False}
        response = client.post(COMPLETION_ROUTE, json=_completion_event(data))
        assert response.status_code == 200
        update.assert_called_once_with("c", file_size=0, increment_completed=False, increment_failed=True)
