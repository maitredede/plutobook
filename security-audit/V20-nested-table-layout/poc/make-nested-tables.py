#!/usr/bin/env python3
# Genuinely nested tables to exercise the intrinsic-width computation.
N = 150
open("nested-tables.html","w").write(
  "<!DOCTYPE html><html><body>" + "<table><tr><td>"*N + "x" + "</td></tr></table>"*N + "</body></html>")
print(f"nested-tables.html written: {N} levels")
