#!/usr/bin/env python3
# Ecrit un HTML dont la chaine CSS `content` se termine par un backslash juste avant EOF.
# L'echappement en fin d'entree produit un string_view vide (data()==nullptr) transmis a
# memcpy dans Heap::createString (UB, detecte par UBSan).
open("repro.html", "wb").write(b'<!DOCTYPE html><html><body><style>p::before{content:"\\')
print("repro.html ecrit (se termine par un backslash + EOF)")
