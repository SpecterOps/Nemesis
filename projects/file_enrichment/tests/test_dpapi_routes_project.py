"""The DPAPI routes and the masterkey monitor keep every key operation inside one project."""

from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest
import pytest_asyncio
from common.models2.dpapi import DpapiCredentialRequest
from nemesis_dpapi import DpapiManager, MasterKey, MasterKeyType
from nemesis_dpapi.eventing import NewPlaintextMasterKeyEvent
from pydantic import TypeAdapter

# The modules create a storage client (which waits for a Dapr sidecar) at import time
with patch("common.storage.StorageS3", MagicMock()):
    from file_enrichment import global_vars
    from file_enrichment.routes import dpapi as routes

ADAPTER = TypeAdapter(DpapiCredentialRequest)
GUID = UUID("ed93694f-5a6d-46e2-b821-219f2c0ecd4d")
DPAPI_SYSTEM_HEX = "dcfd03644f501805c189e15e9367b01415dea75a4e25d96d26879ded571f5d48a6887455d28f66f5"


@pytest_asyncio.fixture
async def manager():
    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as m:
        yield m


@pytest.mark.asyncio
async def test_dpapi_system_credential_is_stored_for_the_requests_project(manager):
    request = ADAPTER.validate_python({"type": "dpapi_system", "value": DPAPI_SYSTEM_HEX, "project": "proj-a"})
    assert (await routes._handle_dpapi_system_credential(manager, request))["status"] == "success"
    assert len(await manager.get_system_credentials(project="proj-a")) == 1
    assert await manager.get_system_credentials(project="proj-b") == []


@pytest.mark.asyncio
async def test_masterkey_pairs_are_stored_for_the_requests_project(manager):
    request = ADAPTER.validate_python(
        {"type": "master_key_guid_pair", "value": [{"guid": str(GUID), "key_hex": "ab" * 20}], "project": "proj-a"}
    )
    result = await routes._handle_master_key_guid_pairs(manager, request)
    assert result["added"] == [str(GUID)]
    assert len(await manager.get_masterkeys(guid=GUID, project="proj-a")) == 1
    assert await manager.get_masterkeys(guid=GUID, project="proj-b") == []

    # The same GUID in another project is independent, not "already exists"
    other = ADAPTER.validate_python(
        {"type": "master_key_guid_pair", "value": [{"guid": str(GUID), "key_hex": "cd" * 20}], "project": "proj-b"}
    )
    assert (await routes._handle_master_key_guid_pairs(manager, other))["added"] == [str(GUID)]


@pytest.mark.asyncio
async def test_password_credential_is_passed_the_requests_project():
    calls = []

    class Decryptor:
        async def process_password_based_credential(self, credential, sid, *, project):
            calls.append(project)
            return {"status": "success"}

    request = ADAPTER.validate_python(
        {"type": "password", "value": "pw", "user_sid": "S-1-5-21-1-2-3-1001", "project": "proj-a"}
    )
    await routes._handle_password_based_credential(Decryptor(), request)
    assert calls == ["proj-a"]


@pytest.mark.asyncio
async def test_masterkey_monitor_retries_only_the_events_project(manager, monkeypatch):
    await manager.upsert_masterkey(
        MasterKey(guid=GUID, masterkey_type=MasterKeyType.SYSTEM, plaintext_key=b"\x01" * 64), project="proj-a"
    )
    seen = {}

    async def chrome_keys(guid, dpapi_manager, pool, masterkey_type, *, project):
        seen["chrome_keys"] = (project, masterkey_type)
        return {}

    async def state_keys(guid, dpapi_manager, pool, masterkey_type, *, project):
        seen["state_keys"] = project
        return {"state_keys_progressed": 1}

    async def chromium_data(guid, dpapi_manager, pool, masterkey_type, *, project):
        seen["chromium_data"] = project
        return {}

    monkeypatch.setattr(routes, "retry_decrypt_chrome_keys_for_masterkey", chrome_keys)
    monkeypatch.setattr(routes, "retry_decrypt_state_keys_for_masterkey", state_keys)
    monkeypatch.setattr(routes, "retry_decrypt_chromium_data", chromium_data)
    monkeypatch.setattr(global_vars, "asyncpg_pool", object())

    await routes.PlaintextMasterKeyMonitor(manager).update(
        NewPlaintextMasterKeyEvent(project="proj-a", masterkey_guid=GUID)
    )
    # The masterkey type comes from this project's copy of the key
    assert seen == {"chrome_keys": ("proj-a", "system"), "state_keys": "proj-a", "chromium_data": "proj-a"}


@pytest.mark.asyncio
async def test_masterkey_monitor_does_not_see_other_projects_keys(manager, monkeypatch):
    await manager.upsert_masterkey(
        MasterKey(guid=GUID, masterkey_type=MasterKeyType.SYSTEM, plaintext_key=b"\x01" * 64), project="proj-a"
    )
    types = []

    async def chrome_keys(guid, dpapi_manager, pool, masterkey_type, *, project):
        types.append((project, masterkey_type))
        return {}

    async def state_keys(*args, **kwargs):
        return {"state_keys_progressed": 0}

    monkeypatch.setattr(routes, "retry_decrypt_chrome_keys_for_masterkey", chrome_keys)
    monkeypatch.setattr(routes, "retry_decrypt_state_keys_for_masterkey", state_keys)
    monkeypatch.setattr(global_vars, "asyncpg_pool", object())

    await routes.PlaintextMasterKeyMonitor(manager).update(
        NewPlaintextMasterKeyEvent(project="proj-b", masterkey_guid=GUID)
    )
    # proj-b has no such key, so its type is unknown (None) rather than proj-a's "system"
    assert types == [("proj-b", None)]
