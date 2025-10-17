"""CNG file enrichment module.

This module processes Windows CNG (Cryptography Next Generation) key files,
parsing their structure and attempting to decrypt DPAPI-protected components.
"""

import struct
from typing import TYPE_CHECKING
from uuid import UUID

import psycopg
import yara_x
from common.db import get_postgres_connection_str
from common.logger import get_logger
from common.models import EnrichmentResult
from common.state_helpers import get_file_enriched, get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.cng_file.cng_parser import (
    BCRYPT_KEY_DATA_BLOB_MAGIC,
    extract_dpapi_blob_from_cng_property,
    extract_final_key_material,
    parse_bcrypt_key_data_blob,
    parse_cng_stream,
)
from file_enrichment_modules.module_loader import EnrichmentModule
from nemesis_dpapi import Blob, BlobDecryptionError, DpapiManager, MasterKeyNotDecryptedError, MasterKeyNotFoundError
from psycopg.rows import dict_row

if TYPE_CHECKING:
    import asyncio

logger = get_logger(__name__)


class CngFileAnalyzer(EnrichmentModule):
    def __init__(self, standalone: bool = False):
        super().__init__("cng_analyzer")
        self.storage = StorageMinio()
        self.dpapi_manager: DpapiManager = None  # type: ignore
        self.loop: asyncio.AbstractEventLoop = None  # type: ignore
        self.workflows = ["default"]
        self._conninfo = get_postgres_connection_str()

        # Yara rule to identify CNG files
        self.yara_rule = yara_x.compile("""
rule is_cng_file
{
    strings:
        // CNG file header pattern:
        // DWORD version (typically 0x00000001)
        // DWORD headerLength (typically 0x00000000)
        // DWORD type (0x22000000 for key files)
        $cng_header = { 01 00 00 00 00 00 00 00 22 00 00 00 }

        // UTF-16LE "Private Key Properties" string commonly found in CNG files
        $priv_key_props = { 50 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 4B 00 65 00 79 00 20 00 50 00 72 00 6F 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 }

        // UTF-16LE "Private Key" string
        $priv_key = { 50 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 4B 00 65 00 79 00 }

        // Modified timestamp property name in UTF-16LE
        $modified = { 4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 }

    condition:
        // CNG header at start of file + characteristic UTF-16LE strings
        $cng_header at 0 and ($priv_key_props or ($priv_key and $modified))
}
""")

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Check if this file should be processed as a CNG file.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """
        file_enriched = get_file_enriched(object_id)

        # CNG files are typically small (< 10KB)
        if file_enriched.size > 10000:
            return False

        if file_path:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
        else:
            file_bytes = self.storage.download_bytes(file_enriched.object_id)

        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0
        return should_run

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process CNG file and extract/decrypt contents.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        return await self._process_async(object_id, file_path)

    async def _process_async(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process CNG file asynchronously.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """

        try:
            file_enriched = await get_file_enriched_async(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name)

            logger.info(f"Processing CNG file: {file_enriched.path} ({file_enriched.object_id})")

            # Parse the CNG file
            if file_path:
                with open(file_path, "rb") as f:
                    cng_file = parse_cng_stream(f)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    with open(temp_file.name, "rb") as f:
                        cng_file = parse_cng_stream(f)

            if not cng_file:
                logger.error(f"Failed to parse CNG file: {file_enriched.path}")
                return None

            logger.info(
                f"Parsed CNG file '{cng_file.name}': "
                f"version={cng_file.version}, type={cng_file.type}, "
                f"has_public_key={cng_file.public_key is not None}, "
                f"has_private_key={cng_file.private_key is not None}, "
                f"has_private_props={cng_file.private_properties is not None}"
            )

            # Display public properties
            if cng_file.public_properties:
                logger.info(f"Found {len(cng_file.public_properties)} public properties:")
                for prop in cng_file.public_properties:
                    logger.info(f"  - {prop.name}: {len(prop.data)} bytes")

            # Attempt to decrypt private properties (DPAPI blob)
            if cng_file.private_properties:
                logger.info("Attempting to decrypt private properties DPAPI blob...")
                await self._decrypt_private_properties(cng_file.private_properties)

            # Attempt to decrypt private key
            private_key_result = None
            if cng_file.private_key:
                logger.info("Attempting to decrypt private key...")
                private_key_result = await self._decrypt_private_key(file_enriched, cng_file.private_key, cng_file.name)

            enrichment_result.results = {
                "cng_file_name": cng_file.name,
                "version": cng_file.version,
                "type": cng_file.type,
                "has_public_key": cng_file.public_key is not None,
                "has_private_key": cng_file.private_key is not None,
                "has_private_properties": cng_file.private_properties is not None,
                "public_properties_count": len(cng_file.public_properties),
            }

            # Add private key decryption results if available
            if private_key_result:
                enrichment_result.results["private_key_masterkey_guid"] = private_key_result["masterkey_guid"]
                enrichment_result.results["private_key_is_decrypted"] = private_key_result["is_decrypted"]
                if private_key_result.get("decrypted_key_hex"):
                    enrichment_result.results["private_key_decrypted_hex"] = private_key_result["decrypted_key_hex"]

            return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error in CNG file processing")
            return None

    async def _decrypt_private_properties(self, private_props_blob: bytes) -> None:
        """Attempt to decrypt private properties DPAPI blob.

        Args:
            private_props_blob: Raw DPAPI blob bytes
        """

        # ref https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/modules/kull_m_key.h#L12
        #   can't forget the null terminator ;)
        cng_key_properties_entropy = b"6jnkd5J3ZdQDtrsu\x00"

        try:
            # Parse as DPAPI blob
            blob = Blob.from_bytes(private_props_blob)
            logger.info(f"Private properties blob uses masterkey: {blob.masterkey_guid}")

            # Attempt decryption
            try:
                decrypted_props = await self.dpapi_manager.decrypt_blob(blob, entropy=cng_key_properties_entropy)
                logger.info(f"Successfully decrypted private properties! Size: {len(decrypted_props)} bytes")

                # Try to parse decrypted properties
                from file_enrichment_modules.cng_file.cng_parser import parse_cng_properties

                properties = parse_cng_properties(decrypted_props)
                if properties:
                    logger.info(f"Found {len(properties)} decrypted private properties:")
                    for prop in properties:
                        logger.info(f"  - {prop.name}: {len(prop.data)} bytes")

            except (MasterKeyNotDecryptedError, MasterKeyNotFoundError) as e:
                logger.debug(
                    f"Cannot decrypt private properties: masterkey {blob.masterkey_guid} not available",
                    reason=type(e).__name__,
                )
            except BlobDecryptionError as e:
                logger.warning(f"Failed to decrypt private properties blob: {e}", masterkey_guid=blob.masterkey_guid)

        except Exception as e:
            logger.warning(f"Error processing private properties as DPAPI blob: {e}")

    async def _store_chrome_key(
        self, file_enriched, masterkey_guid: UUID, encrypted_bytes: bytes, decrypted_bytes: bytes | None = None
    ) -> None:
        """Store Chrome key data in the database.

        Args:
            file_enriched: File enrichment metadata
            masterkey_guid: GUID of the masterkey used to encrypt the key
            encrypted_bytes: Raw DPAPI blob bytes
            decrypted_bytes: Final 32-byte decrypted key material (if available)
        """
        try:
            with psycopg.connect(self._conninfo, row_factory=dict_row) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO chromium.chrome_keys (
                            originating_object_id,
                            agent_id,
                            source,
                            project,
                            key_masterkey_guid,
                            key_bytes_enc,
                            key_bytes_dec,
                            key_is_decrypted
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (key_masterkey_guid) DO UPDATE SET
                            originating_object_id = EXCLUDED.originating_object_id,
                            agent_id = EXCLUDED.agent_id,
                            project = EXCLUDED.project,
                            key_masterkey_guid = EXCLUDED.key_masterkey_guid,
                            key_bytes_enc = EXCLUDED.key_bytes_enc,
                            key_bytes_dec = EXCLUDED.key_bytes_dec,
                            key_is_decrypted = EXCLUDED.key_is_decrypted
                        """,
                        (
                            file_enriched.object_id,
                            file_enriched.agent_id,
                            file_enriched.source,
                            file_enriched.project,
                            masterkey_guid,
                            encrypted_bytes,
                            decrypted_bytes,
                            decrypted_bytes is not None,
                        ),
                    )
                    conn.commit()

            logger.info(
                f"Stored Chrome key for source {file_enriched.source}, "
                f"masterkey {masterkey_guid}, decrypted={decrypted_bytes is not None}"
            )
        except Exception as e:
            logger.error(f"Failed to store Chrome key: {e}")

    async def _decrypt_private_key(
        self, file_enriched, private_key_data: bytes, cng_file_name: str = ""
    ) -> dict | None:
        """Attempt to decrypt private key data and store in database.

        Args:
            file_enriched: File enrichment metadata
            private_key_data: Raw private key bytes (direct DPAPI blob)
            cng_file_name: Name of the CNG file (to check if it's "Google Chromekey1")

        Returns:
            Dict with masterkey_guid, is_decrypted, and decrypted_key_hex (if decrypted)
        """
        try:
            # ref https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/modules/kull_m_key.h#L13
            #   can't forget the null terminator ;)
            cng_key_blob_entropy = b"xT5rZW5qVVbrvpuA\x00"

            # Try to parse as DPAPI blob directly (CNG private keys are direct DPAPI blobs)
            try:
                blob = Blob.from_bytes(private_key_data)
                logger.debug(f"Private key is DPAPI encrypted with masterkey: {blob.masterkey_guid}")
                import base64

                logger.debug(f"blob: {base64.b64encode(blob.encrypted_data).decode('utf-8')}")

                # Attempt decryption
                decrypted_key = None
                final_key_material = None

                try:
                    decrypted_key = await self.dpapi_manager.decrypt_blob(blob, entropy=cng_key_blob_entropy)
                    logger.info(f"Successfully decrypted private key! Size: {len(decrypted_key)} bytes")

                    # Check for BCRYPT_KEY_DATA_BLOB_HEADER
                    await self._check_bcrypt_key_blob(decrypted_key)

                    # Extract final 32-byte key material
                    final_key_material = extract_final_key_material(decrypted_key)
                    if final_key_material:
                        logger.debug("Extracted final 32-byte key material for database storage")

                except (MasterKeyNotDecryptedError, MasterKeyNotFoundError) as e:
                    logger.debug(
                        f"Cannot decrypt private key: masterkey {blob.masterkey_guid} not available",
                        reason=type(e).__name__,
                    )
                except BlobDecryptionError as e:
                    logger.warning(f"Failed to decrypt private key blob: {e}", masterkey_guid=blob.masterkey_guid)

                # Store in database only if this is Google Chromekey1
                if cng_file_name == "Google Chromekey1":
                    await self._store_chrome_key(
                        file_enriched=file_enriched,
                        masterkey_guid=blob.masterkey_guid,
                        encrypted_bytes=private_key_data,
                        decrypted_bytes=final_key_material,
                    )

                # Return results
                result = {"masterkey_guid": str(blob.masterkey_guid), "is_decrypted": final_key_material is not None}
                if final_key_material:
                    result["decrypted_key_hex"] = final_key_material.hex()

                return result

            except Exception as e:
                # If direct parsing fails, try extracting from property wrapper
                logger.debug(f"Direct DPAPI parsing failed ({e}), trying property extraction...")
                dpapi_blob_data = extract_dpapi_blob_from_cng_property(private_key_data)

                if dpapi_blob_data and dpapi_blob_data != private_key_data:
                    logger.debug(f"Extracted {len(dpapi_blob_data)} bytes from property wrapper")
                    try:
                        blob = Blob.from_bytes(dpapi_blob_data)
                        logger.debug(f"Extracted blob uses masterkey: {blob.masterkey_guid}")

                        # Attempt decryption
                        final_key_material = None
                        try:
                            decrypted_key = await self.dpapi_manager.decrypt_blob(blob, entropy=cng_key_blob_entropy)
                            logger.info(
                                f"Successfully decrypted extracted private key! Size: {len(decrypted_key)} bytes"
                            )
                            await self._check_bcrypt_key_blob(decrypted_key)

                            # Extract final 32-byte key material
                            final_key_material = extract_final_key_material(decrypted_key)
                            if final_key_material:
                                logger.info("Extracted final 32-byte key material for database storage")

                        except Exception as decrypt_error:
                            logger.warning(f"Failed to decrypt extracted blob: {decrypt_error}")

                        # Store in database only if this is Google Chromekey1
                        if cng_file_name == "Google Chromekey1":
                            await self._store_chrome_key(
                                file_enriched=file_enriched,
                                masterkey_guid=blob.masterkey_guid,
                                encrypted_bytes=dpapi_blob_data,
                                decrypted_bytes=final_key_material,
                            )

                        # Return results
                        result = {
                            "masterkey_guid": str(blob.masterkey_guid),
                            "is_decrypted": final_key_material is not None,
                        }
                        if final_key_material:
                            result["decrypted_key_hex"] = final_key_material.hex()

                        return result

                    except Exception as e2:
                        logger.warning(f"Failed to process extracted blob: {e2}")
                else:
                    # Not a DPAPI blob, might be plaintext or other format
                    logger.info("Private key is not DPAPI encrypted, checking for BCRYPT format...")
                    await self._check_bcrypt_key_blob(private_key_data)

        except Exception as e:
            logger.warning(f"Error processing private key: {e}")

        return None

    async def _check_bcrypt_key_blob(self, key_data: bytes) -> None:
        """Check if decrypted data contains BCRYPT_KEY_DATA_BLOB.

        Args:
            key_data: Decrypted or plaintext key data
        """
        header = parse_bcrypt_key_data_blob(key_data)

        if header:
            logger.debug(
                f"Found BCRYPT_KEY_DATA_BLOB_HEADER! "
                f"Magic: 0x{header.magic:08X} (KDBM), "
                f"Version: {header.version}, "
                f"Key length: {header.key_data_length} bytes"
            )

            # Extract final 32 bytes
            final_key = extract_final_key_material(key_data)
            if final_key:
                logger.info(f"Extracted final 32-byte key material: {final_key.hex()}")
            else:
                logger.warning("Failed to extract final 32-byte key material")
        else:
            logger.debug(
                f"Key data does not contain BCRYPT_KEY_DATA_BLOB_HEADER "
                f"(magic: 0x{struct.unpack('<I', key_data[:4])[0]:08X} vs expected 0x{BCRYPT_KEY_DATA_BLOB_MAGIC:08X})"
            )


def create_enrichment_module(standalone: bool = False) -> EnrichmentModule:
    """Factory function that creates the analyzer in either standalone or service mode."""
    return CngFileAnalyzer(standalone=standalone)
