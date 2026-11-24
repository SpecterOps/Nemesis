"""Every DPAPI credential request names the project it belongs to (DPAPI key material is scoped per project)."""

import pytest
from common.models2.dpapi import DpapiCredentialRequest
from pydantic import TypeAdapter, ValidationError

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
PAYLOADS = {
    "password": {"type": "password", "value": "pw", "user_sid": SID},
    "cred_key_ntlm": {"type": "cred_key_ntlm", "value": "ab" * 16, "user_sid": SID},
    "cred_key_sha1": {"type": "cred_key_sha1", "value": "ab" * 20, "user_sid": SID},
    "cred_key_pbkdf2": {"type": "cred_key_pbkdf2", "value": "ab" * 16, "user_sid": SID},
    "domain_backup_key": {
        "type": "domain_backup_key",
        "value": "AAAA",
        "guid": "7efa51b1-2523-45bf-acba-2e15ecf4f1e7",
    },
    "master_key_guid_pair": {
        "type": "master_key_guid_pair",
        "value": [{"guid": "7efa51b1-2523-45bf-acba-2e15ecf4f1e7", "key_hex": "ab" * 20}],
    },
    "dpapi_system": {"type": "dpapi_system", "value": "ab" * 40},
    "chromium_app_bound_key": {"type": "chromium_app_bound_key", "value": "ab" * 32, "source": "WS01"},
}
ADAPTER = TypeAdapter(DpapiCredentialRequest)


@pytest.mark.parametrize("credential_type", PAYLOADS)
def test_project_is_kept(credential_type):
    request = ADAPTER.validate_python({**PAYLOADS[credential_type], "project": "proj-a"})
    assert request.type == credential_type
    assert request.project == "proj-a"
    assert request.model_dump()["project"] == "proj-a"


@pytest.mark.parametrize("credential_type", PAYLOADS)
def test_project_is_required(credential_type):
    with pytest.raises(ValidationError, match="project"):
        ADAPTER.validate_python(PAYLOADS[credential_type])


@pytest.mark.parametrize("project", ["", "   ", "\t", None, "p" * 256])
@pytest.mark.parametrize("credential_type", ["password", "dpapi_system", "domain_backup_key"])
def test_blank_project_is_rejected(credential_type, project):
    with pytest.raises(ValidationError, match="project"):
        ADAPTER.validate_python({**PAYLOADS[credential_type], "project": project})


# --- chromium_app_bound_key.source fits chromium.state_keys.source VARCHAR(1000) -------------------------------


@pytest.fixture
def issues(monkeypatch):
    from common import data_issues

    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, e, **kw: calls.append(kw)})())
    return calls


def abe(source):
    return {**PAYLOADS["chromium_app_bound_key"], "project": "p1", "source": source}


@pytest.mark.parametrize(
    ("given", "stored"),
    [
        ("ws01", "host://ws01"),
        ("  ws01  ", "host://ws01"),
        ("host://ws01", "host://ws01"),
        ("smb://srv/x", "smb://srv/x"),
    ],
)
def test_abe_source_is_normalized_once(given, stored, issues):
    assert ADAPTER.validate_python(abe(given)).source == stored
    assert issues == []


def test_abe_source_at_limit_accepted(issues):
    assert len(ADAPTER.validate_python(abe("h" * 993)).source) == 1000
    assert len(ADAPTER.validate_python(abe("host://" + "h" * 993)).source) == 1000


@pytest.mark.parametrize(("source", "reason"), [("", "blank"), ("   ", "blank"), ("h" * 994, "too long")])
def test_abe_source_rejected_and_logged(source, reason, issues):
    with pytest.raises(ValidationError, match="source"):
        ADAPTER.validate_python(abe(source))
    assert issues and issues[-1]["kind"] == "rejected_input" and issues[-1]["reason"] == reason
    assert issues[-1]["field"] == "chromium_app_bound_key.source"
