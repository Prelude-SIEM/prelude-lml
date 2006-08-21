#!/usr/bin/python

import sys, re

for filename in sys.argv[1:]:
    f = open(filename, "r")

    log = [ ]
    while True:
        data = f.readline()
        if not data:
            break

        #grep ".*#[ ]*LOG[ ]*:" | grep -v FIXME | sed s'/.*#[ ]*LOG[ ]*:[ ]*//'

        data.strip()
        
        if re.compile(".*#[ ]*LOG[ ]*:").search(data):
            if data.find("FIXME") != -1:
                continue
            
            log += [ re.compile(".*#[ ]*LOG[ ]*:[ ]*").sub("", data) ]

        if re.compile("regex=").search(data):
            if re.compile("#.*regex=").search(data):
                log = []
            else:
                for i in log:
                    print i[:-1]

                log = []

    f.close()
