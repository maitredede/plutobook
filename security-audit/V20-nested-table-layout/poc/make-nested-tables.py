#!/usr/bin/env python3
# Tables reellement imbriquees pour exercer le calcul de largeur intrinseque.
N = 150
open("nested-tables.html","w").write(
  "<!DOCTYPE html><html><body>" + "<table><tr><td>"*N + "x" + "</td></tr></table>"*N + "</body></html>")
print(f"nested-tables.html ecrit: {N} niveaux")
