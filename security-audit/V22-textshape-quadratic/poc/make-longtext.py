#!/usr/bin/env python3
# Long run de texte simple colonne (beaucoup de lignes) pour exercer positionForOffset O(n^2).
para = ("mot " * 200000).strip()
open("longtext.html", "w").write(
  "<!DOCTYPE html><html><body><p>" + para + "</p></body></html>")
print("longtext.html ecrit")
