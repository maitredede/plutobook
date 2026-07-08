#!/usr/bin/env python3
# Fabrique un fichier 'evil.ttf' malforme (en-tete sfnt tronque) pour exercer le parseur FreeType.
# But: montrer que PlutoBook parse des octets arbitraires sans pre-validation.
open("evil.ttf","wb").write(b"\x00\x01\x00\x00" + b"\x00"*8 + b"\xff"*64)
print("evil.ttf ecrit (a fuzzer sous ASan)")
