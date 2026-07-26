#!/usr/bin/env python3

import pefile
import sys

if len(sys.argv) != 2:
    print("usage: patch_loop.py ntgdi_fuzzer.exe")
    sys.exit(1)

filename = sys.argv[1]

# Ghidra address of the CALL FillRandomBytes instruction
GHIDRA_ADDR = 0x140028F45

pe = pefile.PE(filename)

image_base = pe.OPTIONAL_HEADER.ImageBase
rva = GHIDRA_ADDR - image_base

offset = pe.get_offset_from_rva(rva)

with open(filename, "r+b") as f:
    f.seek(offset)

    original = f.read(5)

    print("Original bytes:", original.hex())

    if original[0] != 0xE8:
        print("WARNING: expected CALL opcode (E8).")

    f.seek(offset)

    f.write(b"\xEB\xFE\x90\x90\x90")

print("Patched.")