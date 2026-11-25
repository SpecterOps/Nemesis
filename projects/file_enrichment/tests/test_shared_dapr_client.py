"""The process-wide Dapr client used for publishes from activities."""

from unittest.mock import MagicMock, patch

import pytest

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.global_vars as global_vars


def test_get_dapr_client_returns_shared_client(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(global_vars, "dapr_client", client)
    assert global_vars.get_dapr_client() is client
    assert global_vars.get_dapr_client() is client  # same instance every call, never a new client


def test_get_dapr_client_before_startup_raises(monkeypatch):
    monkeypatch.setattr(global_vars, "dapr_client", None)
    with pytest.raises(RuntimeError, match="not initialized"):
        global_vars.get_dapr_client()
