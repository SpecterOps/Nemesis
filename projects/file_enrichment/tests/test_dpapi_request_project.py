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


@pytest.mark.parametrize("project", ["", "   ", "\t"])
@pytest.mark.parametrize("credential_type", ["password", "dpapi_system", "domain_backup_key"])
def test_blank_project_is_rejected(credential_type, project):
    with pytest.raises(ValidationError, match="project"):
        ADAPTER.validate_python({**PAYLOADS[credential_type], "project": project})
