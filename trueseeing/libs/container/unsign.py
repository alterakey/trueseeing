#!/usr/bin/env python3
from subprocess import run
import sys

path, outpath = sys.argv[1], sys.argv[2]

run(f"(cd && mkdir t && cd t && unzip -q /out/{path} && rm -rf META-INF && rm -f /out/{outpath} && zip -qr /out/{outpath} .)", shell=True)
