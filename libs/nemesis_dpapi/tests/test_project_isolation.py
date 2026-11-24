"""DPAPI key material is scoped to a project: nothing stored for one project is returned or used for another."""

import asyncio
import base64
import json
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from nemesis_dpapi import DomainBackupKey, DpapiManager, DpapiSystemCredential, MasterKey, MasterKeyType
from nemesis_dpapi.core import Blob, MasterKeyFile
from nemesis_dpapi.exceptions import MasterKeyNotFoundError
from nemesis_dpapi.keys import Password
from nemesis_dpapi.masterkey_decryptor import MasterKeyDecryptorService
from nemesis_dpapi.null_manager import NullDpapiManager
from nemesis_dpapi.repositories import EncryptionFilter
from nemesis_dpapi.storage_postgres import (
    PostgresDomainBackupKeyRepository,
    PostgresDpapiSystemCredentialRepository,
    PostgresMasterKeyRepository,
)

# Real vectors (see test_core.py): the plaintext of masterkey ed93694f..., which decrypts blob_without_entropy.bin,
# and a DPAPI_SYSTEM secret that decrypts masterkey_system.bin.
MASTERKEY_GUID = UUID("ed93694f-5a6d-46e2-b821-219f2c0ecd4d")
MASTERKEY_BYTES = bytes.fromhex(
    "36BD60CB9E7E52433169DB00E93ED0A82D3C30C65D948BD8596FB32C267671020B02026B0AE03479DD18374ADBDD7658F45CCE6ED2A45319EFF7A96C411C85F5"
)
DPAPI_SYSTEM_SECRET = bytes.fromhex(  # machine key + user key, without the 4-byte version header
    "dcfd03644f501805c189e15e9367b01415dea75a4e25d96d26879ded571f5d48a6887455d28f66f5"
)
SYSTEM_MASTERKEY_SHA1 = bytes.fromhex("b848ddc68f5250e5977bc52fd9671811ba3bc3b1")

A, B = "project-a", "project-b"


@pytest.fixture
def backup_key(get_file_path) -> DomainBackupKey:
    data = json.loads(get_file_path("backupkey.json").read_text())
    return DomainBackupKey(guid=UUID(data["backup_key_guid"]), key_data=base64.b64decode(data["key"]))


def plaintext_masterkey() -> MasterKey:
    return MasterKey(guid=MASTERKEY_GUID, masterkey_type=MasterKeyType.UNKNOWN, plaintext_key=MASTERKEY_BYTES)


def encrypted_system_masterkey(get_file_path) -> MasterKey:
    masterkey_file = MasterKeyFile.from_file(get_file_path("masterkey_system.bin"))
    return MasterKey(
        guid=masterkey_file.masterkey_guid,
        masterkey_type=MasterKeyType.SYSTEM,
        encrypted_key_usercred=masterkey_file.master_key,
    )


async def drain(manager: DpapiManager) -> None:
    """Wait for the auto-decrypt observer's background tasks."""
    observer = manager._auto_decrypt_observer
    while observer is not None and observer._background_tasks:
        await asyncio.gather(*list(observer._background_tasks), return_exceptions=True)


# --- in-memory manager -----------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_masterkey_is_only_visible_in_its_project():
    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as manager:
        await manager.upsert_masterkey(plaintext_masterkey(), project=A)

        assert len(await manager.get_masterkeys(guid=MASTERKEY_GUID, project=A)) == 1
        assert await manager.get_masterkeys(guid=MASTERKEY_GUID, project=B) == []
        assert len(await manager.get_masterkeys(project=A)) == 1
        assert await manager.get_masterkeys(project=B, encryption_filter=EncryptionFilter.DECRYPTED_ONLY) == []


@pytest.mark.asyncio
async def test_blob_only_decrypts_with_its_projects_masterkey(blob_without_entropy):
    blob = Blob.from_bytes(blob_without_entropy)
    assert blob.masterkey_guid == MASTERKEY_GUID
    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as manager:
        await manager.upsert_masterkey(plaintext_masterkey(), project=A)

        assert await manager.decrypt_blob(blob, project=A)
        with pytest.raises(MasterKeyNotFoundError):
            await manager.decrypt_blob(blob, project=B)


@pytest.mark.asyncio
async def test_same_guid_is_independent_per_project():
    """Write-once is per project: B can hold a different value for a GUID A already set."""
    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as manager:
        await manager.upsert_masterkey(plaintext_masterkey(), project=A)
        other = MasterKey(guid=MASTERKEY_GUID, masterkey_type=MasterKeyType.UNKNOWN, plaintext_key=b"\x01" * 64)
        await manager.upsert_masterkey(other, project=B)

        (a_key,) = await manager.get_masterkeys(guid=MASTERKEY_GUID, project=A)
        (b_key,) = await manager.get_masterkeys(guid=MASTERKEY_GUID, project=B)
        assert a_key.plaintext_key == MASTERKEY_BYTES
        assert b_key.plaintext_key == b"\x01" * 64


@pytest.mark.asyncio
async def test_backup_keys_and_system_credentials_are_per_project(backup_key):
    guid = backup_key.guid
    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as manager:
        await manager.upsert_domain_backup_key(backup_key, project=A)
        await manager.upsert_system_credential(DpapiSystemCredential.from_bytes(DPAPI_SYSTEM_SECRET), project=A)

        assert len(await manager.get_backup_keys(project=A)) == 1
        assert len(await manager.get_backup_keys(guid=guid, project=A)) == 1
        assert await manager.get_backup_keys(project=B) == []
        assert await manager.get_backup_keys(guid=guid, project=B) == []
        assert len(await manager.get_system_credentials(project=A)) == 1
        assert await manager.get_system_credentials(project=B) == []


@pytest.mark.asyncio
async def test_system_credential_only_auto_decrypts_its_projects_masterkeys(get_file_path):
    """The rest of #39: a DPAPI_SYSTEM secret from project A never decrypts project B's masterkeys."""
    masterkey = encrypted_system_masterkey(get_file_path)
    async with DpapiManager(storage_backend="memory", auto_decrypt=True) as manager:
        await manager.upsert_masterkey(masterkey, project=A)
        await manager.upsert_masterkey(masterkey, project=B)

        await manager.upsert_system_credential(DpapiSystemCredential.from_bytes(DPAPI_SYSTEM_SECRET), project=A)
        await drain(manager)

        (a_key,) = await manager.get_masterkeys(guid=masterkey.guid, project=A)
        (b_key,) = await manager.get_masterkeys(guid=masterkey.guid, project=B)
        assert a_key.is_decrypted and a_key.plaintext_key_sha1 == SYSTEM_MASTERKEY_SHA1
        assert not b_key.is_decrypted


@pytest.mark.asyncio
async def test_new_masterkey_is_decrypted_with_existing_credential_of_same_project_only(get_file_path):
    masterkey = encrypted_system_masterkey(get_file_path)
    async with DpapiManager(storage_backend="memory", auto_decrypt=True) as manager:
        await manager.upsert_system_credential(DpapiSystemCredential.from_bytes(DPAPI_SYSTEM_SECRET), project=A)
        await drain(manager)

        await manager.upsert_masterkey(masterkey, project=B)
        await drain(manager)
        (b_key,) = await manager.get_masterkeys(guid=masterkey.guid, project=B)
        assert not b_key.is_decrypted

        await manager.upsert_masterkey(masterkey, project=A)
        await drain(manager)
        (a_key,) = await manager.get_masterkeys(guid=masterkey.guid, project=A)
        assert a_key.is_decrypted


@pytest.mark.asyncio
async def test_events_carry_the_project(backup_key):
    events = []

    class Recorder:
        async def update(self, event):
            events.append(event)

    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as manager:
        await manager.subscribe(Recorder())
        await manager.upsert_masterkey(plaintext_masterkey(), project=A)
        await manager.upsert_domain_backup_key(backup_key, project=B)
        await manager.upsert_system_credential(DpapiSystemCredential.from_bytes(DPAPI_SYSTEM_SECRET), project=A)

    assert [(type(e).__name__, e.project) for e in events] == [
        ("NewPlaintextMasterKeyEvent", A),
        ("NewDomainBackupKeyEvent", B),
        ("NewDpapiSystemCredentialEvent", A),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("project", ["", "   ", None])
async def test_empty_project_is_rejected(project, blob_without_entropy, backup_key):
    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as manager:
        calls = [
            manager.upsert_masterkey(plaintext_masterkey(), project=project),
            manager.get_masterkeys(project=project),
            manager.upsert_domain_backup_key(backup_key, project=project),
            manager.get_backup_keys(project=project),
            manager.upsert_system_credential(DpapiSystemCredential.from_bytes(DPAPI_SYSTEM_SECRET), project=project),
            manager.get_system_credentials(project=project),
            manager.decrypt_blob(Blob.from_bytes(blob_without_entropy), project=project),
        ]
        for call in calls:
            with pytest.raises(ValueError, match="project"):
                await call


@pytest.mark.asyncio
async def test_project_is_a_required_keyword():
    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as manager:
        with pytest.raises(TypeError):
            await manager.get_masterkeys()  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            await manager.upsert_masterkey(plaintext_masterkey())  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_password_decryptor_requires_project_and_stays_in_it(monkeypatch):
    manager = MagicMock()
    manager.get_masterkeys = AsyncMock(return_value=[])
    service = MasterKeyDecryptorService(manager)
    sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"

    with pytest.raises(ValueError, match="project"):
        await service.process_password_based_credential(Password(value="pw"), sid, project="")

    await service.process_password_based_credential(Password(value="pw"), sid, project=A)
    await asyncio.gather(*list(service._background_tasks))
    assert manager.get_masterkeys.await_args.kwargs["project"] == A


@pytest.mark.asyncio
async def test_null_manager_accepts_project():
    manager = NullDpapiManager()
    assert await manager.get_masterkeys(project=A) == []
    assert await manager.get_backup_keys(project=A) == []
    assert await manager.get_system_credentials(project=A) == []


# --- Postgres repositories (mocked pool) ------------------------------------------------------------------------


def mock_pool(fetchrow=None, fetch=None):
    conn = MagicMock()
    conn.execute = AsyncMock(return_value="INSERT 0 1")
    conn.fetchrow = AsyncMock(return_value=fetchrow)
    conn.fetch = AsyncMock(return_value=fetch or [])
    pool = MagicMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return pool, conn


@pytest.mark.asyncio
async def test_postgres_masterkey_queries_are_project_scoped():
    pool, conn = mock_pool()
    repo = PostgresMasterKeyRepository(pool)

    await repo.upsert_masterkey(plaintext_masterkey(), project=A)
    sql, *params = conn.execute.await_args.args
    assert "ON CONFLICT (project, guid)" in sql and params[0] == A

    await repo.get_masterkeys(guid=MASTERKEY_GUID, project=B)
    sql, *params = conn.fetchrow.await_args.args
    assert "project = $1 AND guid = $2" in sql and params == [B, str(MASTERKEY_GUID)]

    await repo.get_masterkeys(project=B, masterkey_type=[MasterKeyType.SYSTEM], backup_key_guid=MASTERKEY_GUID)
    sql, *params = conn.fetch.await_args.args
    assert sql.split("WHERE", 1)[1].strip().startswith("project = $1") and params[0] == B

    await repo.delete_masterkey(MASTERKEY_GUID, project=A)
    assert conn.execute.await_args.args[1:] == (A, str(MASTERKEY_GUID))


@pytest.mark.asyncio
async def test_postgres_backup_key_and_credential_queries_are_project_scoped(backup_key):
    pool, conn = mock_pool(fetchrow={"id": 7})
    backup_repo = PostgresDomainBackupKeyRepository(pool)
    assert await backup_repo.upsert_backup_key(backup_key, project=A) == 7
    sql, *params = conn.fetchrow.await_args.args
    assert "ON CONFLICT (project, guid)" in sql and params[0] == A

    await backup_repo.get_backup_keys(project=B)
    sql, *params = conn.fetch.await_args.args
    assert "WHERE project = $1" in sql and params == [B]

    cred_repo = PostgresDpapiSystemCredentialRepository(pool)
    await cred_repo.upsert_credential(DpapiSystemCredential.from_bytes(DPAPI_SYSTEM_SECRET), project=A)
    sql, *params = conn.execute.await_args.args
    assert "ON CONFLICT (project, user_key, machine_key)" in sql and params[0] == A

    await cred_repo.get_all_credentials(project=B)
    sql, *params = conn.fetch.await_args.args
    assert "WHERE project = $1" in sql and params == [B]

    await cred_repo.delete_all_credentials(project=A)
    assert conn.execute.await_args.args[1:] == (A,)
