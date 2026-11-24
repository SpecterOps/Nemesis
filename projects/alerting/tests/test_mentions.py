"""Collected data in alert text must not ping people in Slack or Discord."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from alerting.mentions import neutralize_mentions
from common.helpers import sanitize_file_path
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

ZWSP = "\u200b"  # zero-width space


@pytest.mark.parametrize(
    "text",
    [
        "<!channel>",
        "<!here>",
        "<!everyone>",
        "<!subteam^S123ABC>",
        "<@U024BE7LH>",
        "<#C024BE7LR>",
        "<@123456789012345678>",
        "<@&987654321>",
        "@everyone",
        "@here",
        "@channel",
        "@All",
    ],
)
def test_mentions_are_defused(text):
    out = neutralize_mentions(f"report {text} done")
    assert text not in out
    # Still readable: removing the zero-width space gives back the original
    assert out.replace(ZWSP, "") == f"report {text} done"


@pytest.mark.parametrize(
    "text",
    [
        "*<https://nemesis.example/findings?object_id=1|View Finding in Nemesis>*",
        "- *File Path:* C:/Users/alice/notes.txt",
        "alice@example.com wrote @everyoneish and @heresy",
        "a < b and c > d",
        "",
    ],
)
def test_normal_text_and_our_links_are_unchanged(text):
    assert neutralize_mentions(text) == text


def test_none_stays_none():
    assert neutralize_mentions(None) is None


def test_masked_file_path_keeps_the_extension_mention_until_neutralized():
    # sanitize_file_path keeps the extension, which is where a planted mention survives
    masked = sanitize_file_path("C:/loot/report.<!channel>")
    assert masked.endswith("<!channel>")
    assert "<!channel>" not in neutralize_mentions(masked)


@pytest.fixture(autouse=True)
def _initialized():
    alerting_main.is_initialized = True
    alerting_main.alert_settings.update({"alerting_enabled": True, "minimum_severity": 0})


@pytest.mark.asyncio
async def test_sent_alert_title_and_body_are_defused():
    alert = Alert(
        title="titus_<!here>",
        service="file_enrichment",
        severity=9,
        body="- *File Path:* C:/lo****.<!channel>\n*<https://nemesis.example/files?object_id=1|View File in Nemesis>*",
    )
    with patch.object(alerting_main.apobj, "async_notify", new_callable=AsyncMock, return_value=True) as notify:
        assert await alerting_main.send_alert_with_retries(alert) == "sent"
    sent = notify.call_args.kwargs
    assert "<!here>" not in sent["title"] and sent["title"].startswith("[file_enrichment] titus_<")
    assert "<!channel>" not in sent["body"]
    assert "<https://nemesis.example/files?object_id=1|View File in Nemesis>" in sent["body"]
