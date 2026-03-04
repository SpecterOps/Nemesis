"""Tests for alert filtering vs delivery failure distinction."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from common.models import Alert

# Mock DaprClient before importing alerting.main (it runs DaprClient at module level)
_mock_secret = MagicMock()
_mock_secret.secret = {"HASURA_ADMIN_SECRET": "test-secret"}
_mock_dapr = MagicMock()
_mock_dapr.get_secret.return_value = _mock_secret
_mock_dapr.__enter__ = MagicMock(return_value=_mock_dapr)
_mock_dapr.__exit__ = MagicMock(return_value=False)

with patch("dapr.clients.DaprClient", return_value=_mock_dapr):
    import alerting.main as alerting_main  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_alerting_state():
    """Reset global state for each test."""
    alerting_main.is_initialized = True
    alerting_main.alert_settings = {
        "alerting_enabled": True,
        "minimum_severity": 4,
        "category_excluded": [],
        "category_included": [],
        "file_path_excluded_regex": [],
        "file_path_included_regex": [],
        "llm_triage_values_to_alert": ["true_positive"],
    }


@pytest.fixture
def low_severity_alert():
    return Alert(title="Low Severity", body="test", severity=3)


@pytest.fixture
def high_severity_alert():
    return Alert(title="High Severity", body="test", severity=5)


@pytest.fixture
def no_severity_alert():
    return Alert(title="No Severity", body="test")


class TestSendAlertWithRetries:
    """Tests for send_alert_with_retries return values."""

    @pytest.mark.asyncio
    async def test_filtered_alert_returns_filtered(self, low_severity_alert):
        """Alert below severity threshold should return 'filtered', not 'failed'."""
        result = await alerting_main.send_alert_with_retries(low_severity_alert)
        assert result == "filtered"

    @pytest.mark.asyncio
    async def test_disabled_alerting_returns_filtered(self, high_severity_alert):
        """Alert when alerting is globally disabled should return 'filtered'."""
        alerting_main.alert_settings["alerting_enabled"] = False
        result = await alerting_main.send_alert_with_retries(high_severity_alert)
        assert result == "filtered"

    @pytest.mark.asyncio
    async def test_excluded_category_returns_filtered(self):
        """Alert with excluded category should return 'filtered'."""
        alerting_main.alert_settings["category_excluded"] = ["yara_match"]
        alert = Alert(title="Excluded", body="test", category="yara_match", severity=5)
        result = await alerting_main.send_alert_with_retries(alert)
        assert result == "filtered"

    @pytest.mark.asyncio
    async def test_successful_send_returns_sent(self, high_severity_alert):
        """Successfully sent alert should return 'sent'."""
        with patch.object(alerting_main.apobj, "async_notify", new_callable=AsyncMock, return_value=True):
            result = await alerting_main.send_alert_with_retries(high_severity_alert)
        assert result == "sent"

    @pytest.mark.asyncio
    async def test_failed_send_returns_failed(self, high_severity_alert):
        """Alert that fails all retries should return 'failed'."""
        original_retries = alerting_main.MAX_ALERT_RETRIES
        original_delay = alerting_main.RETRY_DELAY_SECONDS
        alerting_main.MAX_ALERT_RETRIES = 1
        alerting_main.RETRY_DELAY_SECONDS = 0
        try:
            with patch.object(alerting_main.apobj, "async_notify", new_callable=AsyncMock, return_value=False):
                result = await alerting_main.send_alert_with_retries(high_severity_alert)
            assert result == "failed"
        finally:
            alerting_main.MAX_ALERT_RETRIES = original_retries
            alerting_main.RETRY_DELAY_SECONDS = original_delay

    @pytest.mark.asyncio
    async def test_uninitialized_returns_failed(self, high_severity_alert):
        """Alert when Apprise is not initialized should return 'failed'."""
        alerting_main.is_initialized = False
        result = await alerting_main.send_alert_with_retries(high_severity_alert)
        assert result == "failed"

    @pytest.mark.asyncio
    async def test_no_severity_alert_not_filtered(self, no_severity_alert):
        """Alert without severity should not be filtered by severity threshold."""
        with patch.object(alerting_main.apobj, "async_notify", new_callable=AsyncMock, return_value=True):
            result = await alerting_main.send_alert_with_retries(no_severity_alert)
        assert result == "sent"


class TestShouldFilterAlert:
    """Tests for the should_filter_alert function."""

    def test_severity_below_threshold(self, low_severity_alert):
        should_filter, reason = alerting_main.should_filter_alert(low_severity_alert)
        assert should_filter is True
        assert "below minimum threshold" in reason

    def test_severity_meets_threshold(self, high_severity_alert):
        should_filter, reason = alerting_main.should_filter_alert(high_severity_alert)
        assert should_filter is False

    def test_alerting_disabled(self, high_severity_alert):
        alerting_main.alert_settings["alerting_enabled"] = False
        should_filter, reason = alerting_main.should_filter_alert(high_severity_alert)
        assert should_filter is True
        assert "globally disabled" in reason

    def test_file_path_excluded_regex(self):
        alerting_main.alert_settings["file_path_excluded_regex"] = [r".*\.tmp$"]
        alert = Alert(title="test", body="test", severity=5, file_path="/data/foo.tmp")
        should_filter, reason = alerting_main.should_filter_alert(alert)
        assert should_filter is True
        assert "excluded regex" in reason
