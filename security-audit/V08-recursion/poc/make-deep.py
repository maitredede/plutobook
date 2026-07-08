#!/usr/bin/env python3
# Two vectors: nested elements and nested CSS blocks.
open("deep.html","w").write("<!DOCTYPE html><html><body>" + "<div>"*200000 + "x" + "</div>"*200000 + "</body></html>")
open("deep.css.html","w").write("<!DOCTYPE html><html><head><style>a:" + "("*200000 + "</style></head><body>x</body></html>")
print("deep.html and deep.css.html written")
