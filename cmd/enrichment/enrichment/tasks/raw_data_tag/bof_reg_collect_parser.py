# Standard Libraries
import base64
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
# REG_RESOURCE_LIST = 8
# REG_FULL_RESOURCE_DESCRIPTOR = 9
# REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD = 11


class RegKey(NamedTuple):
    type_: int
    path: str
    path_size: int
    key: str
    key_size: int
    value: Union[bytes, int, List[bytes]]
    value_size: int


class BofRegCollect:
    def __init__(self, data: bytes):
        self.data = data

    @classmethod
    def from_file(cls, path: str) -> "BofRegCollect":
        with open(path, "rb") as f:
            return cls(f.read())

    def read_unsigned_int(self) -> int:
        (ret,), self.data = struct.unpack(">I", self.data[:4]), self.data[4:]
        return ret

    def read_unsigned_long(self) -> int:
        (ret,), self.data = struct.unpack("<L", self.data[:4]), self.data[4:]
        return ret

    def read_unsigned_long_be(self) -> int:
        (ret,), self.data = struct.unpack(">L", self.data[:4]), self.data[4:]
        return ret

    def read_unsigned_long_long(self) -> int:
        (ret,), self.data = struct.unpack("<Q", self.data[:8]), self.data[8:]
        return ret

    def read_fixed_string(self, length: int) -> bytes:
        (ret,), self.data = struct.unpack(f">{length}s", self.data[:length]), self.data[length:]
        return ret

    def read_string(self) -> Tuple[bytes, int]:
        size = self.read_unsigned_int()
        if size == 0:
            return b"", size
        ret = self.read_fixed_string(size)
        return ret, size

    def read_key(self) -> Tuple[RegKey, bytes]:
        type_ = self.read_unsigned_int()
        path, path_size = self.read_string()
        path = path.decode("utf-16")

        key, key_size = self.read_string()
        key = key.decode("utf-16")
        if key == "(default)":
            key = ""

        value = b""
        value_length = 0

        if type_ == REG_NONE:
            self.read_unsigned_int()
        elif type_ == REG_DWORD:
            self.read_unsigned_int()
            value = self.read_unsigned_long()
        elif type_ == REG_BINARY:
            value, value_length = self.read_string()
            value = base64.b64encode(value).decode("ASCII")
        elif type_ == REG_DWORD_BIG_ENDIAN:
            self.read_unsigned_int()
            value = self.read_unsigned_long_be()
        elif type_ == REG_MULTI_SZ:
            value, value_length = self.read_string()
            value = [v for v in value.decode("utf-16").split("\0") if v != ""]
        elif type_ == REG_QWORD:
            self.read_unsigned_int()
            value = self.read_unsigned_long_long()
        else:
            value, value_length = self.read_string()
            value = value.decode("utf-16").strip("\x00")

        return RegKey(type_, path, path_size, key, key_size, value, value_length)

    def parse(self) -> List[RegKey]:
        arr = []
        arr_size = self.read_unsigned_int()

        for i in range(arr_size):
            reg_key = self.read_key()
            arr.append(reg_key)
        return arr


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python nemesis_reg_parser.py <input file> <output file>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    reg = [k._asdict() for k in BofRegCollect.from_file(input_path).parse()]
    with open(output_path, "w") as f:
        json.dump(reg, f)
