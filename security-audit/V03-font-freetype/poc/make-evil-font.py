#!/usr/bin/env python3
# Builds a malformed 'evil.ttf' file (truncated sfnt header) to exercise the FreeType parser.
# Goal: show that PlutoBook parses arbitrary bytes with no pre-validation.
open("evil.ttf","wb").write(b"\x00\x01\x00\x00" + b"\x00"*8 + b"\xff"*64)
print("evil.ttf written (fuzz it under ASan)")
