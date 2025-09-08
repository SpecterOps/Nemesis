"""Demo showing built-in auto-decryption functionality using test data."""

import asyncio
import base64
import json
from pathlib import Path
from uuid import UUID

from nemesis_dpapi import DomainBackupKey, DpapiManager, MasterKeyFile
from nemesis_dpapi.repositories import MasterKeyFilter


async def main():
    """Demonstrate built-in auto-decryption feature with test data."""
    print("=== Built-in Auto-Decryption Demo (Real Test Data) ===")

    # Load test data fixtures
    fixtures_path = Path(__file__).parent.parent / "tests" / "fixtures"

    # Load backup key from fixtures
    with open(fixtures_path / "backupkey.json") as f:
        backup_key_data = json.load(f)

    # Load masterkey files
    mk_domain_file = fixtures_path / "masterkey_domain.bin"
    mk_local_file = fixtures_path / "masterkey_local.bin"

    mk_domain = MasterKeyFile.parse(mk_domain_file)
    mk_local = MasterKeyFile.parse(mk_local_file)

    # Scenario 1: Add masterkeys first, then backup key
    print("\n📋 Scenario 1: masterkeys added first, then backup key")
    async with DpapiManager(storage_backend="memory") as dpapi:
        # Add encrypted masterkeys first
        print("\n1. Adding encrypted masterkeys...")

        # Domain masterkey (ed93694f-5a6d-46e2-b821-219f2c0ecd4d)
        if mk_domain.master_key and mk_domain.domain_backup_key:
            await dpapi.add_encrypted_masterkey(
                guid=mk_domain.masterkey_guid,
                encrypted_key_usercred=mk_domain.master_key,
                encrypted_key_backup=mk_domain.domain_backup_key,
            )

        # Check initial state
        all_keys = await dpapi.get_all_masterkeys()
        decrypted_keys = await dpapi.get_all_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"Initial state: {len(all_keys)} total, {len(decrypted_keys)} decrypted")

        # Add the domain backup key - this should trigger automatic decryption
        print("\n2. Adding domain backup key (should decrypt domain masterkey)...")
        backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )
        await dpapi.add_domain_backup_key(backup_key)

        # Give the background auto-decryption task a moment to complete
        await asyncio.sleep(0.1)

        # Check final state - should show more decrypted keys if auto-decryption worked
        all_keys_final = await dpapi.get_all_masterkeys()
        decrypted_keys_final = await dpapi.get_all_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"After backup key: {len(all_keys_final)} total, {len(decrypted_keys_final)} decrypted")

        if len(decrypted_keys_final) > len(decrypted_keys):
            print("✓ Auto-decryption successfully decrypted existing masterkeys!")
            for mk in decrypted_keys_final:
                print(f"  Decrypted: {mk.guid} ({len(mk.plaintext_key or b'')} bytes)")
        else:
            print("✗ No masterkeys were auto-decrypted")

    # Scenario 2: Add backup key first, then masterkeys
    print("\n📋 Scenario 2: backup key added first, then masterkeys")
    async with DpapiManager(storage_backend="memory") as dpapi2:
        # Add domain backup key first
        print("\n3. Adding domain backup key first...")
        backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )
        await dpapi2.add_domain_backup_key(backup_key)

        # Check initial state (should have backup key but no masterkeys)
        backup_keys = await dpapi2._backup_key_repo.get_all_backup_keys()
        all_keys_before = await dpapi2.get_all_masterkeys()
        print(f"Initial state: {len(backup_keys)} backup keys, {len(all_keys_before)} masterkeys")

        # Add masterkeys - these should be auto-decrypted using existing backup key
        print("\n4. Adding masterkeys (should be auto-decrypted with existing backup key)...")

        # Domain masterkey
        if mk_domain.master_key and mk_domain.domain_backup_key:
            await dpapi2.add_encrypted_masterkey(
                guid=mk_domain.masterkey_guid,
                encrypted_key_usercred=mk_domain.master_key,
                encrypted_key_backup=mk_domain.domain_backup_key,
            )

        # Local masterkey (won't be decrypted by domain backup key)
        if mk_local.master_key and mk_local.backup_key:
            await dpapi2.add_encrypted_masterkey(
                guid=mk_local.masterkey_guid,
                encrypted_key_usercred=mk_local.master_key,
                encrypted_key_backup=mk_local.backup_key,
            )

        # Give the background auto-decryption task a moment to complete
        await asyncio.sleep(0.1)

        # Check final state
        all_keys_after = await dpapi2.get_all_masterkeys()
        decrypted_keys_after = await dpapi2.get_all_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"After adding masterkeys: {len(all_keys_after)} total, {len(decrypted_keys_after)} decrypted")

        if len(decrypted_keys_after) > 0:
            print("✓ Auto-decryption successfully decrypted new masterkeys!")
            for mk in decrypted_keys_after:
                print(f"  Decrypted: {mk.guid} ({len(mk.plaintext_key or b'')} bytes)")
        else:
            print("✗ No masterkeys were auto-decrypted")

    print("\n=== Comparison: Auto-decryption Disabled ===")

    # Now demonstrate with auto-decryption disabled using data
    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as dpapi_no_auto:
        print("\n5. Adding masterkeys with auto-decryption disabled...")

        if mk_domain.master_key and mk_domain.domain_backup_key:
            await dpapi_no_auto.add_encrypted_masterkey(
                guid=mk_domain.masterkey_guid,
                encrypted_key_usercred=mk_domain.master_key,
                encrypted_key_backup=mk_domain.domain_backup_key,
            )

        # Check state before backup key
        all_keys_before = await dpapi_no_auto.get_all_masterkeys()
        decrypted_keys_before = await dpapi_no_auto.get_all_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"Before backup key: {len(all_keys_before)} total, {len(decrypted_keys_before)} decrypted")

        # Add backup key - should NOT trigger auto-decryption
        backup_key_disabled = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )
        await dpapi_no_auto.add_domain_backup_key(backup_key_disabled)
        await asyncio.sleep(0.1)

        # Check state after backup key
        all_keys_after = await dpapi_no_auto.get_all_masterkeys()
        decrypted_keys_after = await dpapi_no_auto.get_all_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"After backup key: {len(all_keys_after)} total, {len(decrypted_keys_after)} decrypted")

        if len(decrypted_keys_after) == len(decrypted_keys_before):
            print("✓ Auto-decryption correctly disabled - no automatic decryption occurred")

    print("DONE!")


if __name__ == "__main__":
    asyncio.run(main())
