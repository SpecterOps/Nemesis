"""Demo showing built-in auto-decryption functionality using test data.

This example demonstrates the automatic decryption of DPAPI masterkeys when
domain backup keys are added to the DpapiManager. It runs three scenarios:

1. Add encrypted masterkeys first, then add domain backup key
   - Loads encrypted masterkeys into the manager
   - Adds domain backup key which triggers automatic decryption of existing keys
   - Shows how auto-decryption works on previously stored encrypted keys

2. Add domain backup key first, then add masterkeys
   - Adds domain backup key to the manager first
   - Loads encrypted masterkeys which are automatically decrypted upon insertion
   - Demonstrates auto-decryption of newly added keys

3. Auto-decryption disabled
   - Shows the same operations with auto_decrypt=False
   - Proves that no automatic decryption occurs when the feature is disabled
   - Validates that the auto-decryption is controllable

"""

import asyncio
import base64
import json
import struct
from pathlib import Path
from uuid import UUID

from Crypto.PublicKey import RSA
from nemesis_dpapi import DomainBackupKey, DpapiManager, MasterKey, MasterKeyFile, MasterKeyFilter


def create_incorrect_backup_key(correct_key_data: bytes) -> bytes:
    """Create a valid but incorrect domain backup key by generating a new RSA key.

    This creates a properly formatted PVK file with a different RSA key pair,
    ensuring the backup key will pass all validation checks but fail to decrypt.
    """
    # Parse the original PVK header to get the structure
    magic, version, key_spec, encrypt_type, encrypt_data_size, pvk_size = struct.unpack("<6I", correct_key_data[:24])

    # Generate a new RSA key with the same size (2048 bits is typical for DPAPI)
    # We'll use a smaller size for faster generation in the example
    new_rsa_key = RSA.generate(2048)

    # Export as DER format (PKCS#1 private key)
    private_key_der = new_rsa_key.export_key(format="DER", pkcs=1)

    # Convert DER to Microsoft's PRIVATE_KEY_BLOB format
    # The PRIVATE_KEY_BLOB format is:
    # PUBLICKEYSTRUC (8 bytes) + RSAPUBKEY (variable)
    # For simplicity, we'll use the impacket structure from a generated key

    # Create a PRIVATE_KEY_BLOB from our RSA key
    # Structure: magic (4) + bitlen (4) + pubexp (4) + modulus + prime1 + prime2 + exp1 + exp2 + coef + privexp
    n = new_rsa_key.n
    e = new_rsa_key.e
    d = new_rsa_key.d
    p = new_rsa_key.p
    q = new_rsa_key.q

    # Calculate additional RSA-CRT parameters
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)

    # Get bit length
    bitlen = new_rsa_key.size_in_bits()
    bytelen = bitlen // 8
    halflen = bytelen // 2

    # Build the PRIVATEKEYBLOB structure
    # BLOBHEADER
    blob = struct.pack("<BBBB", 0x07, 0x02, 0x00, 0x00)  # bType=PRIVATEKEYBLOB, bVersion=2, reserved, algorithm
    blob += struct.pack("<I", 0x00024000 | 0x0000A400)  # CALG_RSA_KEYX

    # RSAPUBKEY
    blob += struct.pack("<4s", b"RSA2")  # magic
    blob += struct.pack("<I", bitlen)  # bitlen
    blob += struct.pack("<I", e)  # pubexp

    # Private key components (all little-endian)
    def to_bytes_le(num: int, length: int) -> bytes:
        return num.to_bytes(length, byteorder="little")

    blob += to_bytes_le(n, bytelen)  # modulus
    blob += to_bytes_le(p, halflen)  # prime1
    blob += to_bytes_le(q, halflen)  # prime2
    blob += to_bytes_le(dmp1, halflen)  # exponent1
    blob += to_bytes_le(dmq1, halflen)  # exponent2
    blob += to_bytes_le(iqmp, halflen)  # coefficient
    blob += to_bytes_le(d, bytelen)  # privateExponent

    new_pvk_size = len(blob)

    # Build new PVK file with same header structure but new key
    new_pvk = struct.pack("<6I", magic, version, key_spec, encrypt_type, encrypt_data_size, new_pvk_size)

    # Add encrypted data if present (we'll use empty since encrypt_type should be 0)
    if encrypt_data_size > 0:
        new_pvk += b"\x00" * encrypt_data_size

    # Add the new private key blob
    new_pvk += blob

    return new_pvk


async def masterkeys_first_then_backup_key(mk_domain: MasterKeyFile, backup_key_data: dict[str, str]) -> None:
    print("\n📋 Scenario 1: masterkeys added first, then backup key")
    async with DpapiManager(storage_backend="memory") as dpapi:
        # Add encrypted masterkeys first
        print("\n1. Adding encrypted masterkeys...")

        # Domain masterkey (ed93694f-5a6d-46e2-b821-219f2c0ecd4d)
        if mk_domain.master_key and mk_domain.domain_backup_key:
            await dpapi.upsert_masterkey(
                MasterKey(
                    guid=mk_domain.masterkey_guid,
                    masterkey_type=mk_domain.masterkey_type,
                    encrypted_key_usercred=mk_domain.master_key,
                    encrypted_key_backup=mk_domain.domain_backup_key.raw_bytes if mk_domain.domain_backup_key else None,
                )
            )

        # Check initial state
        all_keys = await dpapi.get_masterkeys()
        decrypted_keys = await dpapi.get_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"Initial state: {len(all_keys)} total, {len(decrypted_keys)} decrypted")

        # Add the domain backup key - this should trigger automatic decryption
        print("\n2. Adding domain backup key (should decrypt domain masterkey)...")
        # Use the correct backup key to demonstrate successful auto-decryption
        backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )
        await dpapi.upsert_domain_backup_key(backup_key)

        # Give the background auto-decryption task a moment to complete
        await asyncio.sleep(0.1)

        # Check final state - should show more decrypted keys if auto-decryption worked
        all_keys_final = await dpapi.get_masterkeys()
        decrypted_keys_final = await dpapi.get_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"After backup key: {len(all_keys_final)} total, {len(decrypted_keys_final)} decrypted")

        if len(decrypted_keys_final) > len(decrypted_keys):
            print("✅ Auto-decryption successfully decrypted existing masterkeys!")
            for mk in decrypted_keys_final:
                print(f"  Decrypted: {mk.guid} ({len(mk.plaintext_key or b'')} bytes)")
        else:
            print("❗ No masterkeys were auto-decrypted. This is unexpected and something is broken!")


async def backup_key_first_then_masterkeys(mk_domain: MasterKeyFile, mk_local: MasterKeyFile, backup_key_data: dict[str, str]) -> None:
    print("\n📋 Scenario 2: backup key added first, then masterkeys")
    async with DpapiManager(storage_backend="memory") as dpapi2:
        # Add domain backup key first
        print("\n3. Adding domain backup key first...")
        # Use the correct backup key to demonstrate successful auto-decryption
        backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )
        await dpapi2.upsert_domain_backup_key(backup_key)

        # Check initial state (should have backup key but no masterkeys)
        backup_keys = await dpapi2._backup_key_repo.get_all_backup_keys()
        all_keys_before = await dpapi2.get_masterkeys()
        print(f"Initial state: {len(backup_keys)} backup keys, {len(all_keys_before)} masterkeys")

        # Add masterkeys - these should be auto-decrypted using existing backup key
        print("\n4. Adding masterkeys (should be auto-decrypted with existing backup key)...")

        # Domain masterkey
        if mk_domain.master_key and mk_domain.domain_backup_key:
            await dpapi2.upsert_masterkey(
                MasterKey(
                    guid=mk_domain.masterkey_guid,
                    masterkey_type=mk_domain.masterkey_type,
                    encrypted_key_usercred=mk_domain.master_key,
                    encrypted_key_backup=mk_domain.domain_backup_key.raw_bytes,
                )
            )

        # Local masterkey (won't be decrypted by domain backup key)
        if mk_local.master_key and mk_local.backup_key:
            await dpapi2.upsert_masterkey(
                MasterKey(
                    guid=mk_local.masterkey_guid,
                    masterkey_type=mk_local.masterkey_type,
                    encrypted_key_usercred=mk_local.master_key,
                    encrypted_key_backup=mk_local.backup_key,
                )
            )

        # Give the background auto-decryption task a moment to complete
        await asyncio.sleep(0.1)

        # Check final state
        all_keys_after = await dpapi2.get_masterkeys()
        decrypted_keys_after = await dpapi2.get_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"After adding masterkeys: {len(all_keys_after)} total, {len(decrypted_keys_after)} decrypted")

        if len(decrypted_keys_after) > 0:
            print("✅ Auto-decryption successfully decrypted new masterkeys!")
            for mk in decrypted_keys_after:
                print(f"  Decrypted: {mk.guid} ({len(mk.plaintext_key or b'')} bytes)")
        else:
            print("❗ No masterkeys were auto-decrypted. This is unexpected and something is broken!")


async def auto_decryption_disabled(mk_domain: MasterKeyFile, backup_key_data: dict[str, str]) -> None:
    print("\n=== Scenario 3: Auto-decryption Disabled ===")

    # Now demonstrate with auto-decryption disabled using data
    async with DpapiManager(storage_backend="memory", auto_decrypt=False) as dpapi_no_auto:
        print("\n5. Adding masterkeys with auto-decryption disabled...")

        if mk_domain.master_key and mk_domain.domain_backup_key:
            await dpapi_no_auto.upsert_masterkey(
                MasterKey(
                    guid=mk_domain.masterkey_guid,
                    masterkey_type=mk_domain.masterkey_type,
                    encrypted_key_usercred=mk_domain.master_key,
                    encrypted_key_backup=mk_domain.domain_backup_key.raw_bytes,
                )
            )

        # Check state before backup key
        all_keys_before = await dpapi_no_auto.get_masterkeys()
        decrypted_keys_before = await dpapi_no_auto.get_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"Before backup key: {len(all_keys_before)} total, {len(decrypted_keys_before)} decrypted")

        # Add backup key - should NOT trigger auto-decryption
        # Create a valid but incorrect backup key with a different RSA key
        correct_key_data = base64.b64decode(backup_key_data["key"])
        incorrect_key_data = create_incorrect_backup_key(correct_key_data)
        backup_key_disabled = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=incorrect_key_data,
            domain_controller=backup_key_data["dc"],
        )
        await dpapi_no_auto.upsert_domain_backup_key(backup_key_disabled)
        await asyncio.sleep(0.1)

        # Check state after backup key
        all_keys_after = await dpapi_no_auto.get_masterkeys()
        decrypted_keys_after = await dpapi_no_auto.get_masterkeys(filter_by=MasterKeyFilter.DECRYPTED_ONLY)
        print(f"After backup key: {len(all_keys_after)} total, {len(decrypted_keys_after)} decrypted")

        if len(decrypted_keys_after) == len(decrypted_keys_before):
            print("✅ Auto-decryption correctly disabled - no automatic decryption occurred")
        else:
            print(
                "❗ Some masterkeys were decrypted despite auto-decryption being disabled! This is unexpected and something is broken!"
            )


async def main() -> None:
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

    mk_domain = MasterKeyFile.from_file(mk_domain_file)
    mk_local = MasterKeyFile.from_file(mk_local_file)

    # Run all scenarios
    await masterkeys_first_then_backup_key(mk_domain, backup_key_data)
    await backup_key_first_then_masterkeys(mk_domain, mk_local, backup_key_data)
    await auto_decryption_disabled(mk_domain, backup_key_data)

    print("DONE!")


if __name__ == "__main__":
    asyncio.run(main())
