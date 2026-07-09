#!/usr/bin/env python3
# Writes an HTML file whose CSS `content` string ends with a backslash right before EOF.
# The trailing escape produces an empty string_view (data()==nullptr) passed to
# memcpy in Heap::createString (UB, caught by UBSan).
open("repro.html", "wb").write(b'<!DOCTYPE html><html><body><style>p::before{content:"\\')
print("repro.html written (ends with a backslash + EOF)")
