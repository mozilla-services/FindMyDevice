#! /usr/bin/python
import base64
import sys


f = open(sys.argv[1], "r")
items = []
for line in f.readlines():
    if len(line.strip()) == 0:
        continue
    if line[0] == "{":
        items.append(base64.b64encode(line.strip()))
    else:
        items.append(line.strip())

print ".".join(items)
