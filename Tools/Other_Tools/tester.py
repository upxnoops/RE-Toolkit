#!/usr/bin/python

import os
import sys
import math
import string
import threading

from binascii import hexlify
from diff_match_patch import diff_match_patch

DIFF_DELETE = -1
DIFF_INSERT = 1
DIFF_EQUAL = 0

DIFFS = {-1:"Delete", 1:"Insert", 0:"Equal"}

def is_ascii_str(s):
    for c in s:
        if c not in string.printable:
            return False
    return True

class CDiffThread(threading.Thread):
    def __init__(self, differ, f1, f2):
        threading.Thread.__init__(self)
        
        self.differ = differ
        self.f1 = f1
        self.f2 = f2
        self.result = None
    
    def run(self):
        ret = self.differ.diff_main(open(self.f1, "rb").read(),
                                    open(self.f2, "rb").read(), False)
        self.result = (self.f1, self.f2, ret)

class CFileDiffer(object):
    def __init__(self):
        self._debug = True
        self.file_list = []
        self.results = []
        self.matches = {}
        self.commons = {}
        self.threads = 4
        
        self.differ = diff_match_patch()

    def log(self, msg):
        if self._debug:
            sys.stderr.write("CFileDiffer: %s\n" % msg)
            sys.stderr.flush()

    def clear(self):
        self.results = []
        self.commons = {}
        self.matches = {}
        self.file_list = []

    def addFile(self, filename):
        self.file_list.append(filename)

    def diffFiles(self):
        i = 1
        dones = []
        threads = []
        total = len(self.file_list)
        self.log("Diffing a total of %d file(s)" % total)
        
        for f1 in self.file_list:
            self.log("Diffing file %d out of %d" % (i, total))
            i += 1
            for f2 in self.file_list:
                if f1 == f2:
                    continue
                
                x = [f1, f2]
                x.sort()
                if x in dones:
                    continue
                
                dones.append(x)
                #print "Starting thread for %s - %s" % (f1, f2)
                t = CDiffThread(self.differ, f1, f2)
                t.start()
                threads.append(t)
                #r = self.differ.diff_main(open(f1, "rb").read(), open(f2, "rb").read(), False)
                
                if len(threads) >= self.threads:
                    for t in threads:
                        t.join()
                        self.results.append(t.result)
                    threads = []
        
        for t in threads:
            t.join()
            self.results.append(t.result)
        threads = []
        
        return self.results

    def filterResults(self):
        for result in self.results:
            f1, f2, blocks = result
            local_matches = []
            for block in blocks:
                if block[0] == DIFF_EQUAL and block[1] not in local_matches:
                    local_matches.append(block[1])
                    
                    if self.commons.has_key(block[1]):
                        self.commons[block[1]] += 1
                    else:
                        self.commons[block[1]] = 1
                    
                    if not self.matches.has_key(block[1]):
                        for x in self.file_list:
                            if open(x, "rb").read().find(block[1]) > -1:
                                try:
                                    self.matches[block[1]] += 1
                                except:
                                    self.matches[block[1]] = 1

    def getSimilarities(self, size=4, min_score=50):
        total = len(self.file_list)
        #total = math.factorial(x)/(2*math.factorial(x-2))
        similarities = []
        
        for match in self.matches:
            score = self.matches[match]
            percent = score*100/total
            if len(match) > size and percent >= min_score:
                similarities.append([score, match])
        
        return similarities
        
        """
        for common in self.commons:
            score = self.commons[common]
            percent = score*100/total
            
            if len(common) > size and percent >= min_score:
                similarities.append([score, common])
        return similarities
        """

class CDifferOutputer(object):
    def __init__(self, similarities):
        self.similarities = similarities

    def getHexadecimalValue(self, data):
        s = hexlify(data)
        return " ".join([s[i:i+2] for i in range(0, len(s), 2)])

    def getValue(self, data):
        x = repr(data).strip("'").replace('"', '\\"').replace(r"\t", r"\\t")
        x = x.replace(r"\r", r"\\r").replace(r"\n", r"\\n")
        return x

    def get(self):
        raise "Not implemented!"

class CYaraOutputer(CDifferOutputer):
    def __init__(self, similarities, total):
        CDifferOutputer.__init__(self, similarities)
        
        self.total = total
        self.cur_suffix = ""
        self.var_idx = 0
        self.vars = [ chr(x) for x in range(ord('a'), ord('z')+1) ]
        self.suffix = [ str(i) for i in range(1, 16) ]
        self.suffix.append("")
        self.suffix.sort()

    def getVariable(self):
        var = self.vars[self.var_idx]
        self.var_idx += 1
        if self.var_idx == len(self.vars):
            self.var_idx = 0
            suffix_idx = self.suffix.index(self.cur_suffix)+1
            if suffix_idx == len(self.suffix):
                suffix_idx = 0
            
            self.cur_suffix = self.suffix[suffix_idx]
        
        return "$%s%s" % (var, self.cur_suffix)

    def get(self, rule_name="test", rule_type="test"):
        l = []
        
        l.append("rule %s : %s" % (rule_name, rule_type))
        l.append("{")
        l.append("  strings:")
        vars = {}
        for score, data in self.similarities:
            v = self.getVariable()
            if not vars.has_key(score):
                vars[score] = []
            
            vars[score].append(v)
            #l.append('    %s = "%s"' % (v, self.getValue(data)))
            if is_ascii_str(data) and True:
                l.append('    %s = "%s"' % (v, self.getValue(data)))
            else:
                l.append('    %s = { %s }' % (v, self.getHexadecimalValue(data)))
        
        l.append("")
        l.append("  condition:")
        
        i = 1
        t = len(vars)
        total = len(self.similarities)
        
        for x in vars:
            line = "    (%s)" % (" and ".join(vars[x]))
            if i < t:
                line += " or "
            line = line.ljust(50)
            line += "\t// Matches a total of %d file(s) out of %d" % (x, self.total)
            i += 1
            l.append(line)
        
        #l.append(buf)
        l.append("}")
        
        return "\n".join(l)

class CClamAVOutputer(CDifferOutputer):
    def get(self, malware_name="test", format="old"):
        vars = {}
        for score, data in self.similarities:
            if not vars.has_key(score):
                vars[score] = []
            vars[score].append(data)
        
        l = []
        for x in vars:
            values = []
            for val in vars[x]:
                #values.append(hexlify(val))
                l.append("%s=%s" % (malware_name, hexlify(val)))
            #l.append("%s:0:*:%s" % (malware_name, "|".join(values)))
            #break
            #l.append("%s=%s" % (malware_name, "|".join(values)))
        
        return "\n".join(l)

def main(path, format="yara"):
    dones = []
    commons = {}
    results = []
    file_list = []

    fdiffer = CFileDiffer()

    num = 0
    for root, dirs, files in os.walk(path):
        for name in files:
            filename = os.path.join(root, name)
            fdiffer.addFile(filename)

    total = len(fdiffer.file_list)
    i = 1
    
    results = fdiffer.diffFiles()
    fdiffer.filterResults()
    
    similarities = fdiffer.getSimilarities(size=4, min_score=30)
    
    for simil in similarities:
        score, data = simil
        #print "SCORE %d: %s" % (score, repr(data))
    
    if format == "yara":
        yara = CYaraOutputer(similarities, total)
        print yara.get()
    elif format == "clamav":
        clamav = CClamAVOutputer(similarities)
        print clamav.get()

def diff_prettyHtml(diffs):
    """Convert a diff array into a pretty HTML report.

    Args:
      diffs: Array of diff tuples.

    Returns:
      HTML representation.
    """
    html = []
    i = 0
    for (op, data) in diffs:
        text = (data.replace("&", "&amp;").replace("<", "&lt;")
                   .replace(">", "&gt;").replace("\n", "&para;<br>"))
        if op == DIFF_INSERT:
            html.append("<ins style=\"background:#e6ffe6;\">%s</ins>" % text)
        elif op == DIFF_DELETE:
            html.append("<del style=\"background:#ffe6e6;\">%s</del>" % text)
        if op == DIFF_EQUAL:
            html.append("<span>%s</span>" % text)
    return "".join(html)

def test(f1, f2):
    diff = diff_match_patch()
    buf1 = open(f1, "rb").read()
    buf2 = open(f2, "rb").read()
    result = diff.diff_main(buf1, buf2, False)
    #print result
    print "<font face='courier'>%s</font>" % repr(diff.diff_prettyHtml(result))
    """
    print "Total of %d change(s)" % (len(result)-1)
    for change in result:
        print DIFFS[change[0]], repr(change[1])
    """

def usage():
    print "Usage:", sys.argv[0], "<directory>"

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
    elif len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        test(sys.argv[1], sys.argv[2])

