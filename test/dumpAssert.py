#! /usr/bin/python
import base64
import sys


f = open(sys.argv[1], "r")
a = f.read()
asserts = [a]


for i in asserts:
    el = a.split(".")
    for k in el:
        if k is None:
            exit()
        try:
            print(base64.b64decode(k + "===="[:len(k) % 4]))
        except Exception, e:
            print k
