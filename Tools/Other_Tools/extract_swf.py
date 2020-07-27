import os.path
import struct
import sys
import traceback
import zlib

if len(sys.argv) < 2:
    print >> sys.stderr, "usage: %s <filename>" % sys.argv[0]
    sys.exit(1)
filename = sys.argv[1]
if not filename or not os.path.isfile(filename):
    print >> sys.stderr, "error: unable to read file %s" % repr(filename)
    sys.exit(2)
print >> sys.stderr, "reading %s" % repr(filename)
with open(filename, "rb") as f:
    buffer = f.read()

out_counter = 0
for i in xrange(len(buffer) - 8):
    (id0, id1, id2, version, length) = struct.unpack_from("<BBBBI", buffer, i)
    if ((id0 != ord("F") and id0 != ord("C")) or id1 != ord("W") or
        id2 != ord("S") or version < 6 or version > 10 or length <= 0): 
        continue
    print >> sys.stderr, "found a valid header:"
    print >> sys.stderr, "  id: %c%c%c" % (id0, id1, id2)
    print >> sys.stderr, "  version: %i" % (version)
    print >> sys.stderr, "  length: %u" % (length)
    if id0 == ord("C"):
        swf = "F" + buffer[i + 1:]
        print >> sys.stderr, "  decompressing... ",
        try:
            swf = swf[0:8] + zlib.decompress(swf[8:])
            print >> sys.stderr, "ok."
        except zlib.error, e:
            print >> sys.stderr, e
    else:
        swf = buffer[i:i + length]
    if len(swf) != length:
        print >> sys.stderr, "  error: wrong length (%d)" % len(swf)
    else:
        out_counter += 1
        out_filename = "out%03i.swf" % out_counter
        with open(out_filename, "wb") as f:
            f.write(swf)
        print >> sys.stderr, "  wrote swf to %s." % (out_filename)
