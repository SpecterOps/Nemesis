"""Test auto-decryption with DPAPI data."""

import asyncio
import base64
import json
from pathlib import Path
from uuid import UUID

from dpapi import DomainBackupKey, DpapiManager, MasterKeyFile


async def main():
    """Test auto-decryption with fixtures."""
    print("=== Testing Auto-Decryption ===")

    # Load fixtures
    fixtures_path = Path(__file__).parent.parent / "tests" / "fixtures"
    backup_key_path = fixtures_path / "backupkey.json"
    masterkey_path = fixtures_path / "masterkey_domain.bin"

    # Load backup key from JSON
    with open(backup_key_path) as f:
        backup_key_data = json.load(f)

    # Parse the masterkey file
    masterkey_file = MasterKeyFile.parse(masterkey_path)

    async with DpapiManager(storage_backend="memory") as dpapi:
        print("1. Adding encrypted masterkey...")

        if not masterkey_file or not masterkey_file.master_key or not masterkey_file.domain_backup_key:
            print("✗ Failed to load masterkey file")
            return

        # Add the masterkey with domain backup encryption
        await dpapi.add_encrypted_masterkey(
            guid=masterkey_file.masterkey_guid,
            encrypted_key_usercred=masterkey_file.master_key,  # Won't decrypt without user creds
            encrypted_key_backup=masterkey_file.domain_backup_key,  # Should decrypt with backup key
        )

        # Check initial state
        all_keys = await dpapi.get_all_masterkeys()
        decrypted_keys = await dpapi.get_decrypted_masterkeys()
        print(f"Initial state: {len(all_keys)} total, {len(decrypted_keys)} decrypted")

        print("2. Adding domain backup key...")

        # Create DomainBackupKey from fixture
        backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )

        # Add the backup key - should trigger auto-decryption
        await dpapi.add_domain_backup_key(backup_key)

        # Give auto-decryption a moment to work
        await asyncio.sleep(0.1)

        # Check final state
        all_keys_final = await dpapi.get_all_masterkeys()
        decrypted_keys_final = await dpapi.get_decrypted_masterkeys()
        print(f"After backup key: {len(all_keys_final)} total, {len(decrypted_keys_final)} decrypted")

        if len(decrypted_keys_final) > 0:
            print("✓ Auto-decryption successfully decrypted masterkey!")

            # Verify the decrypted key
            decrypted_mk = decrypted_keys_final[0]
            print(f"Decrypted masterkey GUID: {decrypted_mk.guid}")
            print(f"Plaintext key length: {len(decrypted_mk.plaintext_key) if decrypted_mk.plaintext_key else 0}")
            print(f"SHA1 key length: {len(decrypted_mk.plaintext_key_sha1) if decrypted_mk.plaintext_key_sha1 else 0}")
            print(f"Backup key GUID: {decrypted_mk.backup_key_guid}")

            if decrypted_mk.plaintext_key_sha1:
                print(f"Plaintext: {decrypted_mk.plaintext_key_sha1.hex()}")
        else:
            print("✗ Auto-decryption failed to decrypt masterkey")


if __name__ == "__main__":
    asyncio.run(main())
