#!/usr/bin/env python3
# This code takes the "inner" code, "encrypt" it with the key and dumps it in a temporary stager_temp.s file to be compiled into the full program

import sys

key = [0x28, 0xec, 0xea, 0xb4, 0x30, 0xd3, 0xde, 0x26, 0xd9, 0xb7, 0xb8, 0xee, 0xa0, 0x5e, 0x46, 0xb7, 0xc0, 0x76, 0x7e, 0x7f, 0x51, 0xae, 0xe1, 0x3e, 0xd1, 0xab, 0xef, 0x54, 0xb8, 0xc0, 0xc2, 0xe8]

if len(sys.argv) > 1:
    print("Using " + sys.argv[1] + " directory")
    build_dir = sys.argv[1]
else:
    build_dir = "build"

with open("stager.s", "r") as f:
    stager_code = f.read()

with open(build_dir + "/core.bin", "rb") as f:
    core_code = f.read()

core_code_xored = b''
for i in range(0, len(core_code)):
    core_code_xored += bytes([core_code[i] ^ key[i % len(key)]])

core_code_hexed = str([hex(x) for x in core_code_xored]).replace("'", "").replace("[", "").replace("]", "")

stager_code = stager_code.replace('"ENCODED_INNER"', core_code_hexed)

with open(build_dir + "/stager_temp.s", "w") as f:
    f.write(stager_code)