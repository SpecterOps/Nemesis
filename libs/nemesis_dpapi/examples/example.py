"""Updated example showing DPAPI manager usage with eventing."""

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

    def update(self, event: DpapiEvent) -> None:
        """Handler for different types of DPAPI events."""

        if isinstance(event, NewEncryptedMasterKeyEvent):
            print(f"New encrypted masterkey added: {event.masterkey_guid}")
        elif isinstance(event, NewDomainBackupKeyEvent):
            print(f"New domain backup key added: {event.backup_key_guid}")
        elif isinstance(event, NewPlaintextMasterKeyEvent):
            print(f"New plaintext masterkey added: {event.masterkey_guid}")
        else:
            print(f"Event received: {type(event).__name__}")


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

    masterkey_file = MasterKeyFile.parse(masterkey_file_path)
    backup_key_bytes = base64.b64decode(backup_key_data["key"])
    fake_backup_key_bytes = backup_key_bytes[0:499] + b"\x00" + backup_key_bytes[500:]

    print("\n=== Adding Real DPAPI Data ===")

    print("=== DPAPI Library Usage with Events ===")
    async with DpapiManager(storage_backend="memory") as dpapi:
        # Register custom observer
        dpapi_monitor = MyDpapiEventMonitor()
        dpapi.subscribe(dpapi_monitor)

        # Add masterkeys
        domain_mk_guid = UUID("12345678-1234-5678-9abc-123456789abc")
        await dpapi.add_masterkey(
            MasterKey(
                guid=domain_mk_guid,
                encrypted_key_usercred=masterkey_file.master_key[:-1] + b"\x00",
                encrypted_key_backup=masterkey_file.domain_backup_key[:-1] + b"\x00",
            )
        )

        cred_mk_guid1 = UUID("87654321-4321-8765-cba9-987654321cba")
        await dpapi.add_masterkey(
            MasterKey(
                guid=cred_mk_guid1,
                encrypted_key_usercred=masterkey_file.master_key[:-1] + b"\x00",
                encrypted_key_backup=masterkey_file.domain_backup_key[:-1] + b"\x00",
            )
        )

        cred_mk_guid2 = UUID("11111111-2222-3333-4444-555555555555")
        await dpapi.add_masterkey(
            MasterKey(
                guid=cred_mk_guid2,
                encrypted_key_usercred=b"fake_encrypted_cred_masterkey_data_2",
                encrypted_key_backup=b"fake_encrypted_backup_data_2",
            )
        )

        print("Added 3 masterkeys")

        # Add domain backup key (fake one first)
        backup_key = DomainBackupKey(
            guid=UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            key_data=fake_backup_key_bytes,
        )
        await dpapi.add_domain_backup_key(backup_key)

        # Check results after fake backup key
        all_keys = await dpapi.get_all_masterkeys()
        decrypted_keys = await dpapi.get_all_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"\nAfter fake backup key - Total masterkeys: {len(all_keys)}, Decrypted: {len(decrypted_keys)}")

        if not masterkey_file or not masterkey_file.master_key or not masterkey_file.domain_backup_key:
            raise ValueError("Invalid masterkey file")

        await dpapi.add_masterkey(
            MasterKey(
                guid=masterkey_file.masterkey_guid,
                encrypted_key_usercred=masterkey_file.master_key,
                encrypted_key_backup=masterkey_file.domain_backup_key,
            )
        )

        # Add real backup key
        real_backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )
        await dpapi.add_domain_backup_key(real_backup_key)

        # Give auto-decryption time to work
        await asyncio.sleep(1)

        # Check final results
        all_keys_final = await dpapi.get_all_masterkeys()
        decrypted_keys_final = await dpapi.get_all_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(
            f"After real backup key - Total masterkeys: {len(all_keys_final)}, Decrypted: {len(decrypted_keys_final)}"
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

        blob = Blob.parse(blob_data)
        print(f"Blob masterkey GUID: {blob.masterkey_guid}")

        # Decrypt the blob using the DPAPI manager
        decrypted_blob_data = await dpapi.decrypt_blob(blob)
        print(f"Decrypted blob data: {decrypted_blob_data.decode('utf-8')}")

        # Update domain_mk_guid to use the real one for blob decryption test
        if decrypted_keys_final:
            domain_mk_guid = masterkey_file.masterkey_guid


if __name__ == "__main__":
    asyncio.run(main())
