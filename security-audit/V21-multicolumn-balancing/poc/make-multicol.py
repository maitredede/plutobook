#!/usr/bin/env python3
# Large multicolumn content to exercise balancing.
words = ("word " * 20000).strip()
open("multicol.html","w").write(
  "<!DOCTYPE html><html><head><style>div{columns:3}</style></head><body><div>"+words+"</div></body></html>")
print("multicol.html written")
