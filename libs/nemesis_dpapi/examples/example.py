"""Example showing DPAPI usage with eventing.

To run this example: poetry run python /home/itadmin/code/Nemesis/libs/nemesis_dpapi/examples/example.py
This example demonstrates the complete DPAPI workflow including:

1. Event monitoring setup
   - Creates a custom DpapiObserver to monitor library events
   - Subscribes to events for encrypted masterkeys, domain backup keys, and plaintext masterkeys
   - Shows how to track DPAPI operations in real-time

2. Masterkey management
   - Loads masterkey files and domain backup key
   - Adds multiple encrypted masterkeys to the DpapiManager
   - Demonstrates both fake and real backup key scenarios

3. Domain backup key operations
   - First adds a fake/invalid backup key (shows failed decryption)
   - Then adds the domain backup key
   - Shows automatic decryption of masterkeys when valid backup key is added

4. DPAPI blob decryption
   - Loads an encrypted DPAPI blob
   - Parses the blob to extract its masterkey GUID
   - Decrypts the blob using the previously loaded masterkeys
   - Displays the decrypted plaintext content
"""

import asyncio
import base64
import json
from pathlib import Path
from uuid import UUID

from nemesis_dpapi import Blob, DomainBackupKey, DpapiManager, MasterKey, MasterKeyFile, MasterKeyFilter
from nemesis_dpapi.eventing import (
    DpapiEvent,
    DpapiObserver,
    NewDomainBackupKeyEvent,
    NewEncryptedMasterKeyEvent,
    NewPlaintextMasterKeyEvent,
)


class MyDpapiEventMonitor(DpapiObserver):
    """Class that observes DPAPI events."""

    async def update(self, event: DpapiEvent) -> None:
        """Handler for different types of DPAPI events."""

        name = type(self).__name__

        if isinstance(event, NewEncryptedMasterKeyEvent):
            print(f"{name}: New encrypted masterkey added: {event.masterkey_guid}")
        elif isinstance(event, NewDomainBackupKeyEvent):
            print(f"{name}: New domain backup key added: {event.backup_key_guid}")
        elif isinstance(event, NewPlaintextMasterKeyEvent):
            print(f"{name}: New plaintext masterkey added: {event.masterkey_guid}")
        else:
            print(f"{name}: Event received: {type(event).__name__}")


async def main() -> None:
    """Demonstrate DPAPI library usage with eventing system."""

    # Real/valid DPAPI test data
    fixtures_path = Path(__file__).parent.parent / "tests" / "fixtures"
    backup_key_path = fixtures_path / "backupkey.json"
    masterkey_file_path = fixtures_path / "masterkey_domain.bin"
    blob_path = fixtures_path / "blob_without_entropy.bin"

    # Load and add real masterkey
    with open(backup_key_path) as f:
        backup_key_data = json.load(f)

    masterkey_file = MasterKeyFile.from_file(masterkey_file_path)

    if not masterkey_file or not masterkey_file.master_key or not masterkey_file.domain_backup_key:
        raise ValueError("❗Invalid masterkey file")

    print("\n=== Adding Real DPAPI Data ===")

    print("=== DPAPI Library Usage with Events ===")
    async with DpapiManager(storage_backend="memory") as manager:
        # Register custom observer
        monitor = MyDpapiEventMonitor()
        await manager.subscribe(monitor)

        # Add the real masterkey from the test fixture
        await manager.upsert_masterkey(
            MasterKey(
                guid=masterkey_file.masterkey_guid,
                encrypted_key_usercred=masterkey_file.master_key,
                encrypted_key_backup=masterkey_file.domain_backup_key.raw_bytes,
                masterkey_type=masterkey_file.masterkey_type,
            )
        )

        if len(await manager.get_all_masterkeys(filter_by=MasterKeyFilter.ENCRYPTED_ONLY)) == 1:
            print("[✅] Added 1 masterkey:")
        else:
            raise ValueError("❗Failed to add encrypted masterkey")

        print(f"- MasterKey GUID  : {masterkey_file.masterkey_guid}")
        print(f"- Backup Key GUID : {masterkey_file.domain_backup_key.guid_key}")

        real_backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )
        await manager.upsert_domain_backup_key(real_backup_key)

        print(f"[✅] Added domain backup key: {real_backup_key.guid}")

        # Give auto-decryption time to work
        await asyncio.sleep(1)

        # Check final results
        all_keys_final = await manager.get_all_masterkeys()
        decrypted_keys_final = await manager.get_all_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)

        if len(decrypted_keys_final) == 0:
            raise ValueError("❗ No masterkeys were auto-decrypted. This is unexpected and something is broken!")
        else:
            print(
                f"[✅] Auto-decryption success! Total masterkeys: {len(all_keys_final)}, Decrypted: {len(decrypted_keys_final)}"
            )

        # Print the decrypted masterkeys  in the form of {GUID}:SHA1
        for key in decrypted_keys_final:
            print(f"{key.guid}:{key.plaintext_key_sha1.hex()}")  # type: ignore

        # Demonstrate blob decryption with the blob_without_entropy.bin fixture
        print("\n=== Decrypting DPAPI Blob ===")

        # Load and parse the blob
        with open(blob_path, "rb") as f:
            blob_data = f.read()

        # Parse blob to get its structure and masterkey GUID
        blob = Blob.from_bytes(blob_data)
        print(f"[*] Blob masterkey GUID: {blob.masterkey_guid}")

        # Decrypt the blob using the DPAPI manager
        decrypted_blob_data = await manager.decrypt_blob(blob)
        print(f"[*] Decrypted blob data: {decrypted_blob_data.decode('utf-8')}")

        if decrypted_blob_data == b"test":
            print("[✅] Blob decrypted successfully and matches expected plaintext")


if __name__ == "__main__":
    asyncio.run(main())
