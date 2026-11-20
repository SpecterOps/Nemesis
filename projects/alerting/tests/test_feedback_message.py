"""Tests for the file feedback alert message."""

from unittest.mock import MagicMock, patch

# Mock DaprClient before importing alerting.main (it runs DaprClient at module level)
_mock_secret = MagicMock()
_mock_secret.secret = {"HASURA_ADMIN_SECRET": "test-secret"}
_mock_dapr = MagicMock()
_mock_dapr.get_secret.return_value = _mock_secret
_mock_dapr.__enter__ = MagicMock(return_value=_mock_dapr)
_mock_dapr.__exit__ = MagicMock(return_value=False)

with patch("dapr.clients.DaprClient", return_value=_mock_dapr):
    from alerting.main import build_feedback_message  # noqa: E402

OBJECT_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"


def _feedback(**overrides):
    feedback = {
        "object_id": OBJECT_ID,
        "username": "alice",
        "automated": False,
        "missing_parser": False,
        "missing_file_viewer": False,
        "sensitive_info_not_detected": False,
        "timestamp": "2026-11-20T00:00:00+00:00",
        "files_enriched": {"project": "op-blue"},
    }
    feedback.update(overrides)
    return feedback


def test_message_includes_project_link_user_and_issues():
    body = build_feedback_message(
        _feedback(missing_parser=True, missing_file_viewer=True, sensitive_info_not_detected=True),
        "https://nemesis.example/",
    )
    assert body.split("\n") == [
        f"*object_id:* <https://nemesis.example/files/{OBJECT_ID}|{OBJECT_ID}>",
        "*project:* op-blue",
        "*user*: alice",
        "- 📄 Missing parser",
        "- 👁️ Missing file viewer",
        "- 🔒 Sensitive information not detected",
    ]


def test_message_without_issues_has_only_header_lines():
    body = build_feedback_message(_feedback(), "https://nemesis.example/")
    assert body.count("\n") == 2
    assert "*project:* op-blue" in body


def test_missing_project_falls_back_to_unknown():
    # File row gone (relationship null), no relationship key at all, or an empty/null project value
    for overrides in (
        {"files_enriched": None},
        {"files_enriched": {"project": None}},
        {"files_enriched": {"project": ""}},
    ):
        assert "*project:* unknown" in build_feedback_message(_feedback(**overrides), "https://n/")
    feedback = _feedback()
    del feedback["files_enriched"]
    assert "*project:* unknown" in build_feedback_message(feedback, "https://n/")
