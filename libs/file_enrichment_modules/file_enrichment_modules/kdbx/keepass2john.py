#!/usr/bin/env python3
"""
keepass2john utility (Python port)
Processes KeePass 1.x and 2.x database files into a format suitable for use with JtR.

Original C version by Dhiru Kholia and contributors (https://github.com/openwall/john/blob/bleeding-jumbo/src/keepass2john.c)
    GPL license
"""

import argparse
import base64
import hashlib
import os
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# KeePass file signatures
FILE_SIGNATURE_OLD_1 = 0x9AA2D903
FILE_SIGNATURE_OLD_2 = 0xB54BFB65
FILE_SIGNATURE_1 = 0x9AA2D903
FILE_SIGNATURE_2 = 0xB54BFB67
FILE_SIGNATURE_PRERELEASE_1 = 0x9AA2D903
FILE_SIGNATURE_PRERELEASE_2 = 0xB54BFB66
FILE_VERSION_CRITICAL_MASK = 0xFFFF0000
FILE_VERSION_32_3_1 = 0x00030001
FILE_VERSION_32 = 0x00040001
FILE_VERSION_32_4 = 0x00040000
FILE_VERSION_32_4_1 = 0x00040001


# Header field IDs for KDBX 3/4
class HeaderFieldID:
    END_OF_HEADER = 0
    COMMENT = 1
    CIPHER_ID = 2
    COMPRESSION_FLAGS = 3
    MASTER_SEED = 4
    TRANSFORM_SEED = 5
    TRANSFORM_ROUNDS = 6
    ENCRYPTION_IV = 7
    INNER_RANDOM_STREAM_KEY = 8
    STREAM_START_BYTES = 9
    INNER_RANDOM_STREAM_ID = 10
    KDF_PARAMETERS = 11
    PUBLIC_CUSTOM_DATA = 12


# Inner header field IDs for KDBX 4
class InnerHeaderFieldID:
    END_OF_HEADER = 0
    INNER_RANDOM_STREAM_ID = 1
    INNER_RANDOM_STREAM_KEY = 2
    BINARY = 3


# Cipher UUIDs
CIPHER_AES = b"\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff"
CIPHER_TWOFISH = b"\xad\x68\xf2\x9f\x57\x6f\x4b\xb9\xa3\x6a\xd4\x7a\xf9\x65\x34\x6c"
CIPHER_CHACHA20 = b"\xd6\x03\x8a\x2b\x8b\x6f\x4c\xb5\xa5\x24\x33\x9a\x31\xdb\xb5\x9a"

# KDF UUIDs
KDF_AES = 0xC9D9F39A
KDF_ARGON2D = 0xEF636DDF
KDF_ARGON2ID = 0x9E298B19

DEBUG = False


def read_uint32_le(fp):
    """Read a 32-bit little-endian unsigned integer."""
    data = fp.read(4)
    if len(data) != 4:
        raise EOFError("Unexpected end of file")
    return struct.unpack("<I", data)[0]


def read_uint16_le(fp):
    """Read a 16-bit little-endian unsigned integer."""
    data = fp.read(2)
    if len(data) != 2:
        raise EOFError("Unexpected end of file")
    return struct.unpack("<H", data)[0]


def read_uint64_le(data, size=8):
    """Convert bytes to 64-bit little-endian integer."""
    if len(data) < size:
        data = data + b"\x00" * (size - len(data))
    return struct.unpack("<Q", data[:8])[0]


def bytes_to_hex(data):
    """Convert bytes to hex string."""
    return data.hex()


def get_basename_without_ext(filepath):
    """Get filename without extension."""
    return Path(filepath).stem


def warn(message):
    """Print warning message."""
    print(f"! {message}", file=sys.stderr)


def process_kdbx2_database(fp, filename, keyfile=None):
    """Process KeePass 1.x databases."""
    try:
        enc_flag = read_uint32_le(fp)
        version = read_uint32_le(fp)

        final_randomseed = fp.read(16)
        if len(final_randomseed) != 16:
            raise EOFError("Failed to read final_randomseed")

        enc_iv = fp.read(16)
        if len(enc_iv) != 16:
            raise EOFError("Failed to read enc_iv")

        # num_groups
        read_uint32_le(fp)
        # num_entries
        read_uint32_le(fp)

        contents_hash = fp.read(32)
        if len(contents_hash) != 32:
            raise EOFError("Failed to read contents_hash")

        transf_randomseed = fp.read(32)
        if len(transf_randomseed) != 32:
            raise EOFError("Failed to read transf_randomseed")

        key_transf_rounds = read_uint32_le(fp)

        # Check version
        if (version & FILE_VERSION_CRITICAL_MASK) != (FILE_VERSION_32_3_1 & FILE_VERSION_CRITICAL_MASK):
            warn(f"{filename}: Unsupported file version ({version})!")
            return None

        # Determine algorithm
        if enc_flag & 2:
            algorithm = 0  # AES
        elif enc_flag & 8:
            algorithm = 1  # Twofish
        else:
            warn(f"{filename}: Unsupported file encryption ({enc_flag})!")
            return None

        # Get file size and data size
        current_pos = fp.tell()
        fp.seek(0, 2)  # Seek to end
        filesize = fp.tell()
        fp.seek(current_pos)  # Seek back

        datasize = filesize - 124
        if datasize < 0:
            warn(f"{filename}: Error in validating datasize.")
            return None

        dbname = get_basename_without_ext(filename)

        # Read encrypted data
        fp.seek(124)
        encrypted_data = fp.read(datasize)

        # Build hash string
        result = f"{dbname}:$keepass$*1*{key_transf_rounds}*{algorithm}*"
        result += bytes_to_hex(final_randomseed) + "*"
        result += bytes_to_hex(transf_randomseed) + "*"
        result += bytes_to_hex(enc_iv) + "*"
        result += bytes_to_hex(contents_hash)
        result += f"*1*{datasize}*"
        result += bytes_to_hex(encrypted_data)

        # Handle keyfile
        if keyfile:
            keyfile_part = process_keyfile_v1(keyfile)
            if keyfile_part:
                result += keyfile_part

        return result

    except Exception as e:
        warn(f"{filename}: Error processing KDBX2 database: {e}")
        return None


def process_keyfile_v1(keyfile_path):
    """Process keyfile for KeePass 1.x."""
    try:
        with open(keyfile_path, "rb") as kf:
            keyfile_data = kf.read()

        result = "*1*64*"

        if len(keyfile_data) == 32:
            result += bytes_to_hex(keyfile_data)
        elif len(keyfile_data) == 64:
            result += keyfile_data.decode("ascii", errors="ignore")
        else:
            # Hash the keyfile content
            sha256_hash = hashlib.sha256(keyfile_data).digest()
            result += bytes_to_hex(sha256_hash)

        return result

    except Exception as e:
        warn(f"Error processing keyfile {keyfile_path}: {e}")
        return None


def process_keyfile_v2(keyfile_path):
    """Process keyfile for KeePass 2.x."""
    try:
        with open(keyfile_path, "rb") as kf:
            keyfile_data = kf.read()

        result = "*1*64*"

        # Check if it's an XML keyfile
        if keyfile_data.startswith(b"<?xml"):
            try:
                root = ET.fromstring(keyfile_data.decode("utf-8"))
                data_elem = root.find(".//Data")
                if data_elem is not None and data_elem.text:
                    # Decode base64 data and convert to hex
                    decoded = base64.b64decode(data_elem.text)
                    result += bytes_to_hex(decoded)
                    return result
            except:
                pass  # Fall through to other methods

        if len(keyfile_data) == 32:
            result += bytes_to_hex(keyfile_data)
        elif len(keyfile_data) == 64:
            result += keyfile_data.decode("ascii", errors="ignore")
        else:
            # Hash the keyfile content
            sha256_hash = hashlib.sha256(keyfile_data).digest()
            result += bytes_to_hex(sha256_hash)

        return result

    except Exception as e:
        warn(f"Error processing keyfile {keyfile_path}: {e}")
        return None


def parse_variant_dictionary(data):
    """Parse KDBX 4 VariantDictionary."""
    pos = 0
    version = struct.unpack("<H", data[pos : pos + 2])[0]
    pos += 2

    if DEBUG:
        print(f"VariantDictionary version {version >> 8}.{version & 0xFF}", file=sys.stderr)

    if (version >> 8) != 1:
        raise ValueError(f"Unsupported VariantDictionary version ({version:04x})")

    result = {}

    while pos < len(data):
        if pos >= len(data):
            break

        type_byte = data[pos]
        if type_byte == 0:  # Null terminator
            break
        pos += 1

        # Read key name length
        key_len = struct.unpack("<I", data[pos : pos + 4])[0]
        pos += 4

        # Read key name
        key_name = data[pos : pos + key_len].decode("utf-8")
        pos += key_len

        # Read value length
        value_len = struct.unpack("<I", data[pos : pos + 4])[0]
        pos += 4

        # Read value based on type
        value_data = data[pos : pos + value_len]
        pos += value_len

        if type_byte == 0x04:  # UInt32
            value = struct.unpack("<I", value_data)[0]
        elif type_byte == 0x05:  # UInt64
            value = struct.unpack("<Q", value_data)[0]
        elif type_byte == 0x08:  # Bool
            value = value_data[0] != 0
        elif type_byte == 0x0C:  # Int32
            value = struct.unpack("<i", value_data)[0]
        elif type_byte == 0x0D:  # Int64
            value = struct.unpack("<q", value_data)[0]
        elif type_byte == 0x18:  # String
            value = value_data.decode("utf-8")
        elif type_byte == 0x42:  # Byte array
            value = value_data
        else:
            if DEBUG:
                print(f"Unknown type {type_byte:02x} for key {key_name}", file=sys.stderr)
            value = value_data

        result[key_name] = value

        if DEBUG:
            print(f"  {key_name}: {value}", file=sys.stderr)

    return result


def process_database(filename, keyfile=None):
    """Process KeePass database file."""
    try:
        with open(filename, "rb") as fp:
            # Read signatures
            sig1 = read_uint32_le(fp)
            sig2 = read_uint32_le(fp)

            # Check for KeePass 1.x
            if sig1 == FILE_SIGNATURE_OLD_1 and sig2 == FILE_SIGNATURE_OLD_2:
                return process_kdbx2_database(fp, filename, keyfile)

            # Check for KeePass 2.x
            if not (
                (sig1 == FILE_SIGNATURE_1 and sig2 == FILE_SIGNATURE_2)
                or (sig1 == FILE_SIGNATURE_PRERELEASE_1 and sig2 == FILE_SIGNATURE_PRERELEASE_2)
            ):
                warn(f"{filename}: Unknown format: File signature invalid")
                return None

            version = read_uint32_le(fp)

            if (version & FILE_VERSION_CRITICAL_MASK) > (FILE_VERSION_32 & FILE_VERSION_CRITICAL_MASK):
                warn(f"{filename}: Unknown format: File version '{version:x}' unsupported")
                return None

            if DEBUG:
                print(f"\n{filename}", file=sys.stderr)

            # Parse headers
            master_seed = None
            transform_seed = None
            initialization_vectors = None
            expected_start_bytes = None
            transform_rounds = 0
            algorithm = 0
            kdf_uuid = 0
            argon2_p = 0
            argon2_v = 0
            argon2_m = 0

            end_reached = False
            while not end_reached:
                field_id = fp.read(1)
                if len(field_id) != 1:
                    break
                field_id = field_id[0]

                if version < FILE_VERSION_32_4:
                    size = read_uint16_le(fp)
                else:
                    size = read_uint32_le(fp)

                data = fp.read(size) if size > 0 else b""

                if field_id == HeaderFieldID.END_OF_HEADER:
                    end_reached = True
                elif field_id == HeaderFieldID.MASTER_SEED:
                    master_seed = data
                elif field_id == HeaderFieldID.TRANSFORM_SEED:
                    transform_seed = data
                elif field_id == HeaderFieldID.TRANSFORM_ROUNDS:
                    if len(data) >= 4:
                        transform_rounds = struct.unpack("<I", data[:4])[0]
                elif field_id == HeaderFieldID.ENCRYPTION_IV:
                    initialization_vectors = data
                elif field_id == HeaderFieldID.STREAM_START_BYTES:
                    expected_start_bytes = data
                elif field_id == HeaderFieldID.CIPHER_ID:
                    if data.startswith(CIPHER_AES[:4]):
                        algorithm = 0
                    elif data.startswith(CIPHER_TWOFISH[:4]):
                        algorithm = 1
                    elif data.startswith(CIPHER_CHACHA20[:4]):
                        algorithm = 2
                    else:
                        warn(f"{filename}: Unsupported CipherID found!")
                elif field_id == HeaderFieldID.KDF_PARAMETERS:
                    try:
                        params = parse_variant_dictionary(data)
                        if "R" in params or "I" in params:
                            transform_rounds = int(params.get("R", params.get("I", 0)))
                        if "P" in params:
                            argon2_p = int(params["P"])
                        if "V" in params:
                            argon2_v = int(params["V"])
                        if "M" in params:
                            argon2_m = int(params["M"])
                        if "S" in params:
                            transform_seed = params["S"]
                        if "$UUID" in params:
                            uuid_bytes = params["$UUID"]
                            if len(uuid_bytes) >= 4:
                                kdf_uuid = struct.unpack(">I", uuid_bytes[:4])[0]  # Big-endian for UUID
                    except Exception as e:
                        if DEBUG:
                            print(f"Error parsing KDF parameters: {e}", file=sys.stderr)
                # Ignore other fields

            # Validate required fields
            if transform_rounds == 0:
                warn(f"{filename}: transformRounds can't be 0")
                return None

            if version < FILE_VERSION_32_4 and (
                not master_seed or not transform_seed or not initialization_vectors or not expected_start_bytes
            ):
                warn(f"{filename}: parsing failed, missing required fields")
                return None

            dbname = get_basename_without_ext(filename)
            kdbx_ver = version >> 16

            result = ""

            if kdbx_ver < 4:
                # KDBX 3.x
                encrypted_data = fp.read(32)
                if len(encrypted_data) != 32:
                    warn(f"{filename}: error reading encrypted data!")
                    return None

                result = f"dbname:$keepass$*2*{transform_rounds}*{algorithm}*"
                result += bytes_to_hex(master_seed) + "*"
                result += bytes_to_hex(transform_seed) + "*"
                result += bytes_to_hex(initialization_vectors) + "*"
                result += bytes_to_hex(expected_start_bytes) + "*"
                result += bytes_to_hex(encrypted_data)
            else:
                # KDBX 4.x
                header_end_pos = fp.tell()

                # Calculate header hash
                fp.seek(0)
                header_data = fp.read(header_end_pos)
                header_hash_calc = hashlib.sha256(header_data).digest()

                # Read stored header hash
                header_hash_stored = fp.read(32)
                if len(header_hash_stored) != 32:
                    warn(f"{filename}: error reading header hash!")
                    return None

                if header_hash_calc != header_hash_stored:
                    warn(f"{filename}: header hash mismatch - database corrupt?")

                # Read header HMAC
                header_hmac = fp.read(32)
                if len(header_hmac) != 32:
                    warn(f"{filename}: error reading header HMAC!")
                    return None

                result = (
                    f"{dbname}:$keepass$*{kdbx_ver}*{transform_rounds}*{kdf_uuid:08x}*{argon2_m}*{argon2_v}*{argon2_p}*"
                )
                result += bytes_to_hex(master_seed) + "*"
                result += bytes_to_hex(transform_seed) + "*"
                result += bytes_to_hex(header_data) + "*"
                result += bytes_to_hex(header_hmac)

            # Handle keyfile
            if keyfile:
                keyfile_part = process_keyfile_v2(keyfile)
                if keyfile_part:
                    result += keyfile_part

            return result

    except Exception as e:
        warn(f"{filename}: Error processing database: {e}")
        return None


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Extract hash from KeePass database files for John the Ripper")
    parser.add_argument("-k", "--keyfile", help="Path to keyfile")
    parser.add_argument("databases", nargs="+", help="KeePass database files (.kdbx)")

    args = parser.parse_args()

    for database in args.databases:
        if not os.path.exists(database):
            warn(f"File not found: {database}")
            continue

        print(process_database(database, args.keyfile))


if __name__ == "__main__":
    main()
