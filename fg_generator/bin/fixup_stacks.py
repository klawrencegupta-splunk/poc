#!/usr/bin/env python
#
# fixup_stacks.py -- Scrubs pstacks from a given collection into a consistent format
# that can be ingested by other scripts (mainly getstacks.py) to produce a flamegraph
#

import json,re,argparse
import os
from dateutil.parser import parse
import datetime


def is_date(string):
	try:
		parse(string)
		return True
	except ValueError:
		return False


result=[]

parser=argparse.ArgumentParser(description='Generate')
parser.add_argument('--files',dest='files',nargs='+',action='store',default=None,help='inputfiles')
parser.add_argument('--outputDir',dest='outputDir',action='store',default=None,help='outputDir')

args=parser.parse_args()

fileList = args.files
outputDir = args.outputDir

for file in fileList:
    f=open(file,'r')
    fNew=open(outputDir+"/"+os.path.basename(file),'w')
    update_filename_w_date = False
    for line in f:
        if line.startswith("PID"):
            continue
        if line.startswith("  ["):
            continue
        if line.startswith("0x00"):
            continue
        if line.startswith("Using"):
            continue
        if line.startswith("syscall"):
            continue
        if line.startswith("  /"):
            continue
        if line.startswith("  -"):
            continue
        if is_date(line):
        	update_filename_w_date = True
        	ts = parse(line)
        	date_append = ts.strftime('%Y-%m-%dT%Hh%Mm%Ss-0500')
        	continue
        if line.startswith("TID "):
        	line = line.replace("TID ", "Thread ")
        if line.startswith("Thread"):
        	fNew.write("\n")
        fNew.write(line)
    if update_filename_w_date:
    	os.rename(outputDir+"/"+os.path.basename(file), outputDir+"/"+os.path.basename(file)+"-"+date_append)

