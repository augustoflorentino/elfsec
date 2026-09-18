"""What ELFkickers sstrip does to an ELF, as OpenWrt ships its binaries.

usage: python3 -I tests/oracle/sstrip.py IN OUT

Drops the section header table and every byte after the last one a segment maps (or the
program header table ends), and zeroes e_shoff, e_shnum and e_shstrndx. Segments are kept
byte for byte. ELFkickers' optional removal of trailing zero bytes (-z) is not done.
"""

import struct
import sys
from pathlib import Path

def sstrip(data: bytes) -> bytes:
    if data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError("not an ELF file")
    is64, order = data[4] == 2, "<" if data[5] == 1 else ">"
    if is64:
        phoff, shoff = struct.unpack_from(order + "QQ", data, 32)
        phentsize, phnum = struct.unpack_from(order + "HH", data, 54)
    else:
        phoff, shoff = struct.unpack_from(order + "II", data, 28)
        phentsize, phnum = struct.unpack_from(order + "HH", data, 42)
    end = max(phoff + phentsize * phnum, 64 if is64 else 52)
    for i in range(phnum):
        at = phoff + i * phentsize
        if is64:
            offset, filesz = struct.unpack_from(order + "Q", data, at + 8)[0], struct.unpack_from(order + "Q", data, at + 32)[0]
        else:
            offset, filesz = struct.unpack_from(order + "I", data, at + 4)[0], struct.unpack_from(order + "I", data, at + 16)[0]
        if filesz:
            end = max(end, offset + filesz)
    out = bytearray(data[:end])
    if is64:
        struct.pack_into(order + "Q", out, 40, 0)
        struct.pack_into(order + "HH", out, 60, 0, 0)
    else:
        struct.pack_into(order + "I", out, 32, 0)
        struct.pack_into(order + "HH", out, 48, 0, 0)
    return bytes(out)

if __name__ == "__main__":
    Path(sys.argv[2]).write_bytes(sstrip(Path(sys.argv[1]).read_bytes()))
