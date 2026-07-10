#!/usr/bin/env python3
# Long single-column text run (many lines) to exercise O(n^2) positionForOffset.
para = ("word " * 200000).strip()
open("longtext.html", "w").write(
  "<!DOCTYPE html><html><body><p>" + para + "</p></body></html>")
print("longtext.html written")
