import json
import struct
import sys
from typing import List, NamedTuple, Tuple, Union

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD = 11


def read_unsigned_int(data: bytes) -> Tuple[int, bytes]:
    (ret,), data = struct.unpack(">I", data[:4]), data[4:]
    return ret, data


def read_unsigned_long(data: bytes) -> Tuple[int, bytes]:
    (ret,), data = struct.unpack("<L", data[:4]), data[4:]
    return ret, data


def read_unsigned_long_be(data: bytes) -> Tuple[int, bytes]:
    (ret,), data = struct.unpack(">L", data[:4]), data[4:]
    return ret, data


def read_unsigned_long_long(data: bytes) -> Tuple[int, bytes]:
    (ret,), data = struct.unpack("<Q", data[:8]), data[8:]
    return ret, data


def read_fixed_string(data: bytes, length: int) -> Tuple[bytes, bytes]:
    (ret,) = struct.unpack(f">{length}s", data[:length])
    return ret, data[length:]


def read_string(data: bytes) -> Tuple[bytes, int, bytes]:
    size, data = read_unsigned_int(data)
    if size == 0:
        return b"", size, data
    ret, data = read_fixed_string(data, size)
    return ret, size, data


class RegKey(NamedTuple):
    type_: int
    path: str
    path_size: int
    key: str
    key_size: int
    value: Union[bytes, int, List[bytes]]
    value_size: int


def read_key(data: bytes) -> Tuple[RegKey, bytes]:
    type_, data = read_unsigned_int(data)
    path, path_size, data = read_string(data)
    path = path.decode("utf-16")

    key, key_size, data = read_string(data)
    key = key.decode("utf-16")

    value = b""
    value_length = 0

    if type_ == REG_NONE:
        _, data = read_unsigned_int(data)
        value = None
    elif type_ == REG_DWORD:
        _, data = read_unsigned_int(data)
        value, data = read_unsigned_long(data)
    elif type_ in [REG_BINARY, REG_RESOURCE_LIST, REG_FULL_RESOURCE_DESCRIPTOR, REG_LINK]:
        value, value_length, data = read_string(data)
        value = list(value)
    elif type_ == REG_DWORD_BIG_ENDIAN:
        _, data = read_unsigned_int(data)
        value, data = read_unsigned_long_be(data)
    elif type_ == REG_MULTI_SZ:
        value, value_length, data = read_string(data)
        value = [v for v in value.decode("utf-16").split("\0") if v != ""]
    elif type_ == REG_QWORD:
        _, data = read_unsigned_int(data)
        value, data = read_unsigned_long_long(data)
    else:
        value, value_length, data = read_string(data)
        try:
            value = value.decode("utf-16")
        except Exception:
            value = value.decode("latin-1")

    return RegKey(type_, path, path_size, key, key_size, value, value_length), data


def parse_serialized_reg_data(input_path: str) -> List[Tuple[RegKey, bytes]]:
    with open(input_path, "rb") as f:
        data = f.read()
        arr = []
        arr_size, data = read_unsigned_int(data)

        for i in range(arr_size):
            reg_key, data = read_key(data)
            arr.append(reg_key._asdict())

        return arr


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python nemesis_reg_parser.py <input file> <output file>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    parsed_data = parse_serialized_reg_data(input_path)
    with open(output_path, "w") as f:
        json.dump(parsed_data, f)
