#!/usr/bin/env python

"""
AUTHOR:
  Sebastien Damaye (aldeid.com)

VERSION:
  1.1

UPDATED:
  2014-01-22 - Added pydot import to automatically generate png output
  2014-01-17 - Initial release

DESCRIPTION:
  This program is meant to be used with pdf-parser from Didier Stevens.
  It reads the output from pdf-parser and creates the map of the objects flows
  under the form of a DOT file. You can then use the dot utility to export an
  image (e.g. PNG file)

USAGE:
  $ ./pdf-parser pdf.pdf | ./pdfobjflow.py -
"""

import re
import sys
try:
    import pydot
except:
    print "You must install pydot:"
    print "  sudo aptitude install python-pydot"
    sys.exit()

f = sys.stdin.readlines()
o = open("pdfobjflow.dot", "w")

o.write("digraph G {\n")

for l in f:
    m1 = re.match(r"obj (\w+) (\w+)", l)
    m2 = re.match(r" Referencing: (.*)", l)
    if m1:
        obj = "%s.%s" % m1.group(1, 2)
    if m2:
        ref = filter(None, m2.group(1).split(", "))
        if len(ref)==0:
            o.write( "\"%s\";\n" % obj )
        else:
            for r in ref:
                o.write( "\"%s\"->\"%s\";\n" % (obj, r.replace(" ", ".").replace(".R", "")) )

o.write("}")
o.close()

graph = pydot.graph_from_dot_file('pdfobjflow.dot')
graph.write_png('pdfobjflow.png')

