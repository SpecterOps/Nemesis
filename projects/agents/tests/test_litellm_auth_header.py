"""LiteLLM sits behind the Nemesis basic auth, so every client must send its key in x-litellm-api-key."""

from unittest.mock import MagicMock, patch

import httpx
import pytest
from agents import litellm_startup
from agents.helpers import create_rate_limit_client
from agents.litellm_startup import LITELLM_KEY_HEADER, litellm_auth_headers
from agents.model_manager import ModelManager
from agents.phoenix_cost_sync import fetch_litellm_model_info

KEY = "sk-test-key"


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status = status
        self._payload = payload or {}

    async def json(self):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """Stands in for aiohttp.ClientSession and records each request."""

    def __init__(self, responses):
        self.calls = []
        self._responses = list(responses)

    def _request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self._responses.pop(0)

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def assert_litellm_auth(headers, key):
    assert headers[LITELLM_KEY_HEADER] == f"Bearer {key}"
    # Authorization is the Nemesis basic auth header on the /llm route; LiteLLM ignores it
    assert "Authorization" not in headers


def test_litellm_auth_headers():
    assert litellm_auth_headers(KEY) == {"x-litellm-api-key": f"Bearer {KEY}"}


def test_litellm_config_reads_the_same_header():
    from pathlib import Path

    import yaml

    config = Path(__file__).resolve().parents[3] / "infra" / "litellm" / "config.yml"
    settings = yaml.safe_load(config.read_text())["general_settings"]
    assert settings["litellm_key_header_name"] == LITELLM_KEY_HEADER


@pytest.mark.asyncio
async def test_wait_for_litellm_sends_admin_key_header():
    session = FakeSession([FakeResponse(200)])
    with (
        patch.object(litellm_startup, "LITELLM_ADMIN_KEY", KEY),
        patch.object(litellm_startup.aiohttp, "ClientSession", return_value=session),
    ):
        assert await litellm_startup.wait_for_litellm() is True
    assert_litellm_auth(session.calls[0][2]["headers"], KEY)


@pytest.mark.asyncio
async def test_wait_for_litellm_unauthorized_is_not_ready():
    session = FakeSession([FakeResponse(401), FakeResponse(401)])
    with (
        patch.object(litellm_startup, "LITELLM_ADMIN_KEY", "sk-wrong"),
        patch.object(litellm_startup, "RETRY_DELAY", 0),
        patch.object(litellm_startup.aiohttp, "ClientSession", return_value=session),
    ):
        assert await litellm_startup.wait_for_litellm() is False


@pytest.mark.asyncio
async def test_validate_token_sends_token_header():
    session = FakeSession([FakeResponse(200)])
    with patch.object(litellm_startup.aiohttp, "ClientSession", return_value=session):
        assert await litellm_startup.validate_token("sk-user") is True
    assert_litellm_auth(session.calls[0][2]["headers"], "sk-user")


@pytest.mark.asyncio
async def test_validate_token_rejected():
    session = FakeSession([FakeResponse(401)])
    with patch.object(litellm_startup.aiohttp, "ClientSession", return_value=session):
        assert await litellm_startup.validate_token("sk-bad") is False


@pytest.mark.asyncio
async def test_create_token_admin_calls_use_key_header():
    # /user/new fails (user exists), then /key/generate succeeds
    session = FakeSession([FakeResponse(400), FakeResponse(200, {"key": "sk-new"})])
    with (
        patch.object(litellm_startup, "LITELLM_ADMIN_KEY", KEY),
        patch.object(litellm_startup.aiohttp, "ClientSession", return_value=session),
    ):
        assert await litellm_startup.create_new_token() == "sk-new"
    assert [c[1].rsplit("/", 1)[1] for c in session.calls] == ["new", "generate"]
    for _, _, kwargs in session.calls:
        assert_litellm_auth(kwargs["headers"], KEY)
        assert kwargs["headers"]["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_fetch_model_info_sends_key_header():
    seen = {}

    def handler(request: httpx.Request):
        seen.update(request.headers)
        return httpx.Response(200, json={"data": []})

    real_client = httpx.AsyncClient
    with patch(
        "agents.phoenix_cost_sync.httpx.AsyncClient",
        lambda *a, **kw: real_client(transport=httpx.MockTransport(handler)),
    ):
        assert await fetch_litellm_model_info(KEY) == {"data": []}
    assert seen["x-litellm-api-key"] == f"Bearer {KEY}"
    assert "authorization" not in seen


@pytest.mark.asyncio
async def test_fetch_model_info_unauthorized_returns_none():
    real_client = httpx.AsyncClient
    with patch(
        "agents.phoenix_cost_sync.httpx.AsyncClient",
        lambda *a, **kw: real_client(transport=httpx.MockTransport(lambda r: httpx.Response(401))),
    ):
        assert await fetch_litellm_model_info("sk-bad") is None


def test_rate_limit_client_default_headers():
    client = create_rate_limit_client(headers=litellm_auth_headers(KEY))
    assert client.headers["x-litellm-api-key"] == f"Bearer {KEY}"
    assert "x-litellm-api-key" not in create_rate_limit_client().headers


def test_model_manager_client_sends_key_header():
    ModelManager._model = None
    with patch("agents.model_manager.setup_phoenix_llm_tracing", return_value=False):
        ModelManager.initialize(KEY)
    try:
        model = ModelManager.get_model()
        assert model is not None
        # pydantic-ai builds an AsyncOpenAI client on top of our httpx client
        http_client = model.client._client
        assert http_client.headers["x-litellm-api-key"] == f"Bearer {KEY}"
    finally:
        ModelManager._model = None
        ModelManager._token = None


def test_model_manager_uninitialized_has_no_model():
    ModelManager._model = None
    ModelManager._token = None
    assert ModelManager.get_model() is None


@pytest.mark.asyncio
async def test_get_litellm_token_lists_models_with_key_header():
    from agents import helpers

    fake_openai = MagicMock()
    fake_openai.return_value.models.list.return_value.data = [MagicMock(id="default")]

    async def fake_startup():
        return KEY

    with (
        patch.object(helpers, "litellm_startup", fake_startup),
        patch.object(helpers.openai, "OpenAI", fake_openai),
    ):
        assert await helpers.get_litellm_token() == KEY
    assert fake_openai.call_args.kwargs["default_headers"] == {"x-litellm-api-key": f"Bearer {KEY}"}
