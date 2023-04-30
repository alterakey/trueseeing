#!/usr/bin/env python3
import sys
from subprocess import run

inpath, outpath = sys.argv[1], sys.argv[2]
run(f'java -jar /app/zipalign.jar {inpath} {outpath}', shell=True)
