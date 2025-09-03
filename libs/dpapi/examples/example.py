"""Updated example showing DPAPI manager usage with eventing."""

import asyncio
import base64
import json
from pathlib import Path
from uuid import UUID

from dpapi import DomainBackupKey, DpapiManager, MasterKeyFile
from dpapi.eventing import DpapiEvent, DpapiObserver, NewDomainBackupKeyEvent, NewEncryptedMasterKeyEvent


class MyDpapiEventMonitor(DpapiObserver):
    """Class that observes DPAPI events."""

    def update(self, event: DpapiEvent) -> None:
        """Handler for different types of DPAPI events."""

        if isinstance(event, NewEncryptedMasterKeyEvent):
            print(f"New encrypted masterkey added: {event.masterkey_guid}")
        elif isinstance(event, NewDomainBackupKeyEvent):
            print(f"New domain backup key added: {event.backup_key_guid}")
        else:
            print(f"Event received: {type(event).__name__}")


async def main() -> None:
    """Demonstrate DPAPI library usage with eventing system."""

    print("=== DPAPI Library Usage with Events ===")
    async with DpapiManager(storage_backend="memory") as dpapi:
        # Register custom observer
        dpapi_monitor = MyDpapiEventMonitor()
        dpapi.subscribe(dpapi_monitor)

        # Add masterkeys
        domain_mk_guid = UUID("12345678-1234-5678-9abc-123456789abc")
        await dpapi.add_encrypted_masterkey(
            guid=domain_mk_guid,
            encrypted_key_usercred=b"fake_encrypted_usercred_data",
            encrypted_key_backup=b"fake_encrypted_backup_data",
        )

        cred_mk_guid1 = UUID("87654321-4321-8765-cba9-987654321cba")
        await dpapi.add_encrypted_masterkey(
            guid=cred_mk_guid1,
            encrypted_key_usercred=b"fake_encrypted_cred_masterkey_data_1",
            encrypted_key_backup=b"fake_encrypted_backup_data_1",
        )

        cred_mk_guid2 = UUID("11111111-2222-3333-4444-555555555555")
        await dpapi.add_encrypted_masterkey(
            guid=cred_mk_guid2,
            encrypted_key_usercred=b"fake_encrypted_cred_masterkey_data_2",
            encrypted_key_backup=b"fake_encrypted_backup_data_2",
        )

        print("Added 3 masterkeys")

        # Add domain backup key (fake one first)
        backup_key = DomainBackupKey(
            guid=UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            key_data=b"fake_backup_key_data_32_bytes_long",
        )
        await dpapi.add_domain_backup_key(backup_key)

        # Check results after fake backup key
        all_keys = await dpapi.get_all_masterkeys()
        decrypted_keys = await dpapi.get_decrypted_masterkeys()
        print(f"\nAfter fake backup key - Total masterkeys: {len(all_keys)}, Decrypted: {len(decrypted_keys)}")

        # Try with real DPAPI data if available
        fixtures_path = Path(__file__).parent.parent / "tests" / "fixtures"
        backup_key_path = fixtures_path / "test_backupkey.json"
        masterkey_path = fixtures_path / "test_masterkey_domain.bin"

        if backup_key_path.exists() and masterkey_path.exists():
            print("\n=== Adding Real DPAPI Data ===")

            # Load and add real masterkey
            with open(backup_key_path) as f:
                backup_key_data = json.load(f)

            masterkey_file = MasterKeyFile.parse(masterkey_path)

            if not masterkey_file or not masterkey_file.master_key or not masterkey_file.domain_backup_key:
                raise ValueError("Invalid masterkey file")

            await dpapi.add_encrypted_masterkey(
                guid=masterkey_file.masterkey_guid,
                encrypted_key_usercred=masterkey_file.master_key,
                encrypted_key_backup=masterkey_file.domain_backup_key,
            )

            # Add real backup key
            real_backup_key = DomainBackupKey(
                guid=UUID(backup_key_data["backup_key_guid"]),
                key_data=base64.b64decode(backup_key_data["key"]),
                domain_controller=backup_key_data["dc"],
            )
            await dpapi.add_domain_backup_key(real_backup_key)

            # Give auto-decryption time to work
            await asyncio.sleep(0.1)

            # Check final results
            all_keys_final = await dpapi.get_all_masterkeys()
            decrypted_keys_final = await dpapi.get_decrypted_masterkeys()
            print(
                f"After real backup key - Total masterkeys: {len(all_keys_final)}, Decrypted: {len(decrypted_keys_final)}"
            )

            # Update domain_mk_guid to use the real one for blob decryption test
            if decrypted_keys_final:
                domain_mk_guid = masterkey_file.masterkey_guid


if __name__ == "__main__":
    asyncio.run(main())
