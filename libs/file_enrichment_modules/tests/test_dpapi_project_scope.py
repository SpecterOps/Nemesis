"""DPAPI key material is scoped to the project of the file it came from (#39 and the DPAPI project isolation)."""

import inspect
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from file_enrichment_modules.dpapi_blob.analyzer import DpapiBlobAnalyzer
from file_enrichment_modules.registry_hive.analyzer import RegistryHiveAnalyzer
from nemesis_dpapi import DpapiManager, MasterKey, MasterKeyType

from tests.harness import FileEnrichedFactory, ModuleTestHarness

DPAPI_FIXTURES = Path(__file__).resolve().parents[2] / "nemesis_dpapi" / "tests" / "fixtures"
# Plaintext of masterkey ed93694f-..., which decrypts nemesis_dpapi's blob_without_entropy.bin fixture
MASTERKEY_GUID = UUID("ed93694f-5a6d-46e2-b821-219f2c0ecd4d")
MASTERKEY_BYTES = bytes.fromhex(
    "36BD60CB9E7E52433169DB00E93ED0A82D3C30C65D948BD8596FB32C267671020B02026B0AE03479DD18374ADBDD7658F45CCE6ED2A45319EFF7A96C411C85F5"
)


@pytest.mark.asyncio
async def test_registry_hive_registers_dpapi_system_with_the_hives_project():
    module = RegistryHiveAnalyzer.__new__(RegistryHiveAnalyzer)
    module.dpapi_manager = MagicMock()
    module.dpapi_manager.upsert_system_credential = AsyncMock()

    await module._register_dpapi_system_credential(b"m" * 20, b"u" * 20, "proj-a")

    cred = module.dpapi_manager.upsert_system_credential.await_args.args[0]
    assert (cred.machine_key, cred.user_key) == (b"m" * 20, b"u" * 20)
    assert module.dpapi_manager.upsert_system_credential.await_args.kwargs == {"project": "proj-a"}


def test_security_hive_processing_requires_a_project():
    parameter = inspect.signature(RegistryHiveAnalyzer._process_security_hive).parameters["project"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


async def run_dpapi_blob(project: str, masterkey_project: str):
    """Run the dpapi_blob module on a file in ``project`` with the masterkey stored in ``masterkey_project``."""
    blob_path = DPAPI_FIXTURES / "blob_without_entropy.bin"
    harness = ModuleTestHarness()
    harness.register_file(
        object_id="blob",
        local_path=str(blob_path),
        file_enriched=FileEnrichedFactory.create(
            object_id="blob", file_name="blob.bin", size=blob_path.stat().st_size, project=project
        ),
    )
    manager = DpapiManager(storage_backend="memory", auto_decrypt=False)
    await manager.upsert_masterkey(
        MasterKey(guid=MASTERKEY_GUID, masterkey_type=MasterKeyType.UNKNOWN, plaintext_key=MASTERKEY_BYTES),
        project=masterkey_project,
    )
    async with harness.create_module(DpapiBlobAnalyzer) as module:
        module.dpapi_manager = manager
        return await module.process("blob", str(blob_path))


def blob_states(result) -> list[bool]:
    return [blob["is_decrypted"] for blob in result.results["blobs"]]


@pytest.mark.asyncio
async def test_blob_is_decrypted_with_a_masterkey_of_its_own_project():
    result = await run_dpapi_blob(project="proj-a", masterkey_project="proj-a")
    assert result is not None and blob_states(result) and all(blob_states(result))


@pytest.mark.asyncio
async def test_blob_is_not_decrypted_with_another_projects_masterkey():
    result = await run_dpapi_blob(project="proj-b", masterkey_project="proj-a")
    assert result is not None and blob_states(result) and not any(blob_states(result))
