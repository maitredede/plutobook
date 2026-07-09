#!/usr/bin/env python3
# Gros contenu multicolonne pour exercer le balancing.
words = ("mot " * 20000).strip()
open("multicol.html","w").write(
  "<!DOCTYPE html><html><head><style>div{columns:3}</style></head><body><div>"+words+"</div></body></html>")
print("multicol.html ecrit")
