#!/usr/bin/env python3
# Petit BMP 24 bits de largeur 'impaire' pour la voie stb.
import struct
W, H = 13, 4
row = (b"\x10\x20\x30")*W
pad = (-len(row)) % 4
data = b"".join(row + b"\x00"*pad for _ in range(H))
off = 54
bmp = b"BM" + struct.pack("<IHHI", off+len(data), 0, 0, off)
bmp += struct.pack("<IiiHHIIiiII", 40, W, H, 1, 24, 0, len(data), 2835, 2835, 0, 0)
open("odd.bmp","wb").write(bmp + data)
print("odd.bmp ecrit")
