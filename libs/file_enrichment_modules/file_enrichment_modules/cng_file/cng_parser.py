"""Windows CNG file parser and decryptor.

This module parses Windows CNG (Cryptography Next Generation) key files
and attempts to decrypt their contents using DPAPI.
"""

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from uuid import UUID

from common.logger import get_logger

logger = get_logger(__name__)


BCRYPT_KEY_DATA_BLOB_MAGIC = 0x4D42444B     # 'KDBM'
BCRYPT_RSAPUBLIC_MAGIC = 0x31415352         # 'RSA1'
BCRYPT_RSAPRIVATE_MAGIC = 0x32415352        # 'RSA2'
BCRYPT_RSAFULLPRIVATE_BLOB = 0x33415352     # 'RSA3'


@dataclass
class CngPropertyHeader:
    """CNG property header structure."""
    name_length: int
    property_length: int
    name: str
    data: bytes


@dataclass
class CngKeyFile:
    """Parsed CNG key file structure."""
    version: int
    header_length: int
    type: int
    name_length: int
    public_length: int
    private_length: int
    privprop_length: int
    unknown: int
    name: str
    public_properties: list[CngPropertyHeader]
    public_key: bytes | None
    private_properties: bytes | None    # DPAPI blob
    private_key: bytes | None           # May be DPAPI encrypted


@dataclass
class BcryptKeyDataBlobHeader:
    """BCRYPT_KEY_DATA_BLOB_HEADER structure."""
    magic: int
    version: int
    key_data_length: int


def parse_cng_properties(data: bytes, offset: int = 0) -> list[CngPropertyHeader]:
    """Parse CNG property headers from binary data.

    Args:
        data: Binary data containing properties
        offset: Starting offset in data

    Returns:
        List of parsed CNG property headers
    """
    properties = []
    pos = offset

    while pos < len(data):
        if pos + 8 > len(data):
            break

        # Read property header: name_length (4) + property_length (4)
        name_len, prop_len = struct.unpack("<II", data[pos:pos + 8])
        pos += 8

        if name_len == 0 or prop_len == 0:
            break

        # Read property name (UTF-16LE)
        if pos + name_len > len(data):
            break

        name = data[pos:pos + name_len].decode("utf-16le", errors="ignore").rstrip("\x00")
        pos += name_len

        # Read property data
        if pos + prop_len > len(data):
            break

        prop_data = data[pos:pos + prop_len]
        pos += prop_len

        properties.append(CngPropertyHeader(
            name_length=name_len,
            property_length=prop_len,
            name=name,
            data=prop_data
        ))

    return properties


def extract_dpapi_blob_from_cng_property(data: bytes) -> bytes | None:
    """Extract DPAPI blob from a CNG property structure.

    The private key in CNG files is wrapped in a property structure:
    - dwStructLen (4 bytes)
    - type (4 bytes)
    - unk (4 bytes)
    - dwNameLen (4 bytes)
    - dwPropertyLen (4 bytes)
    - pName (variable, UTF-16LE)
    - pProperty (dwPropertyLen bytes) <- This contains the DPAPI blob

    Args:
        data: Raw private key data from CNG file

    Returns:
        Extracted DPAPI blob or None if parsing fails
    """
    if len(data) < 20:  # Minimum header size
        return None

    try:
        # Parse CNG property header
        struct_len, prop_type, unk, name_len, property_len = struct.unpack("<IIIII", data[:20])

        logger.debug(
            f"CNG property: struct_len={struct_len}, type={prop_type}, "
            f"name_len={name_len}, property_len={property_len}"
        )

        # Calculate offset to property data
        # Header (20 bytes) + name (name_len bytes)
        property_offset = 20 + name_len

        if property_offset + property_len > len(data):
            logger.error(f"Property data extends beyond buffer: offset={property_offset}, len={property_len}, data_len={len(data)}")
            return None

        # Extract the property data (should be DPAPI blob)
        dpapi_blob = data[property_offset:property_offset + property_len]

        # Verify it looks like a DPAPI blob (starts with version 0x00000001)
        if len(dpapi_blob) >= 4:
            version = struct.unpack("<I", dpapi_blob[:4])[0]
            if version == 1:
                logger.debug(f"Successfully extracted DPAPI blob from CNG property, size={len(dpapi_blob)}")
                return dpapi_blob
            else:
                logger.warning(f"Extracted data doesn't look like DPAPI blob: version=0x{version:08X}")

        return dpapi_blob

    except Exception as e:
        logger.error(f"Error extracting DPAPI blob from CNG property: {e}")
        return None


def parse_cng_file(file_path: str | Path) -> CngKeyFile | None:
    """Parse a Windows CNG key file.

    Args:
        file_path: Path to the CNG file

    Returns:
        Parsed CngKeyFile or None if parsing fails
    """
    try:
        with open(file_path, "rb") as f:
            return parse_cng_stream(f)
    except Exception as e:
        logger.error(f"Error parsing CNG file {file_path}: {e}")
        return None


def parse_cng_stream(stream: BinaryIO) -> CngKeyFile | None:
    """Parse a Windows CNG key file from a stream.

    Args:
        stream: Binary stream containing CNG data

    Returns:
        Parsed CngKeyFile or None if parsing fails
    """
    try:
        # Read main header (44 bytes)
        # Structure: version(4) + unk(4) + name_len(4) + type(4) +
        #           public_len(4) + privprop_len(4) + privkey_len(4) + unkArray[16]
        header_data = stream.read(44)
        if len(header_data) < 44:
            logger.error("CNG file too short for header")
            return None

        # Parse header fields
        (version, unk, name_len, key_type,
         public_len, privprop_len, privkey_len) = struct.unpack(
            "<IIIIIII", header_data[:28]
        )

        # Read unkArray[16] - last 16 bytes of header
        unk_array = header_data[28:44]

        logger.debug(
            f"CNG header: version={version}, unk={unk}, name_len={name_len}, "
            f"type={key_type}, pub_len={public_len}, "
            f"privprop_len={privprop_len}, privkey_len={privkey_len}"
        )

        # Read key name (name_len bytes, UTF-16LE, null-terminated)
        if name_len > 0:
            name_bytes = stream.read(name_len)
            if len(name_bytes) < name_len:
                logger.error(f"Unexpected EOF reading key name: expected {name_len}, got {len(name_bytes)}")
                return None
            name = name_bytes.decode("utf-16le", errors="ignore").rstrip("\x00")
        else:
            name = ""
            name_bytes = b""

        # Read public properties
        public_properties = []
        if public_len > 0:
            public_data = stream.read(public_len)
            if len(public_data) < public_len:
                logger.error("Unexpected EOF reading public properties")
                return None
            public_properties = parse_cng_properties(public_data)

        # No separate public key section in this format
        public_key = None

        # Read private properties DPAPI blob (privprop_len bytes)
        private_properties = None
        if privprop_len > 0:
            private_properties = stream.read(privprop_len)
            if len(private_properties) < privprop_len:
                logger.error(f"Unexpected EOF reading private properties: expected {privprop_len}, got {len(private_properties)}")
                return None

        # Read private key DPAPI blob (privkey_len bytes)
        private_key = None
        if privkey_len > 0:
            private_key = stream.read(privkey_len)
            if len(private_key) < privkey_len:
                logger.error(f"Unexpected EOF reading private key: expected {privkey_len}, got {len(private_key)}")
                return None

        return CngKeyFile(
            version=version,
            header_length=unk,
            type=key_type,
            name_length=name_len,
            public_length=public_len,
            private_length=privkey_len,
            privprop_length=privprop_len,
            unknown=unk,
            name=name,
            public_properties=public_properties,
            public_key=public_key,
            private_properties=private_properties,
            private_key=private_key
        )

    except Exception as e:
        logger.error(f"Error parsing CNG stream: {e}")
        return None


def parse_bcrypt_key_data_blob(data: bytes) -> BcryptKeyDataBlobHeader | None:
    """Parse BCRYPT_KEY_DATA_BLOB_HEADER from decrypted data.

    Args:
        data: Decrypted private key data

    Returns:
        Parsed header or None if invalid
    """
    if len(data) < 12:
        return None

    magic, version, key_len = struct.unpack("<III", data[:12])

    if magic != BCRYPT_KEY_DATA_BLOB_MAGIC:
        return None

    return BcryptKeyDataBlobHeader(
        magic=magic,
        version=version,
        key_data_length=key_len
    )


def extract_final_key_material(decrypted_data: bytes) -> bytes | None:
    """Extract final 32-byte key material from BCRYPT_KEY_DATA_BLOB.

    Args:
        decrypted_data: Decrypted private key data with KDBM header

    Returns:
        Final 32 bytes of key material or None if invalid
    """
    header = parse_bcrypt_key_data_blob(decrypted_data)
    if not header:
        return None

    # Key data follows the 12-byte header
    if len(decrypted_data) < 12 + header.key_data_length:
        logger.error(f"Decrypted data too short: expected {12 + header.key_data_length}, got {len(decrypted_data)}")
        return None

    # Extract the last 32 bytes of the key data
    key_data_start = 12
    key_data_end = 12 + header.key_data_length
    key_data = decrypted_data[key_data_start:key_data_end]

    if len(key_data) < 32:
        logger.error(f"Key data too short for 32-byte extraction: {len(key_data)} bytes")
        return None

    return key_data[-32:]