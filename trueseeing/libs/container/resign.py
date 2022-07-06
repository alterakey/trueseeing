#!/usr/bin/env python3
import re
from glob import glob
from subprocess import run
import sys
import os

path, outpath, keystorepath = sys.argv[1], sys.argv[2], sys.argv[3]

def _sigfile() -> str:
    try:
        fn = [os.path.basename(fn) for fn in glob(os.path.expanduser(f"~/t/META-INF/*.SF"))][0]
        print(f"found existing signature: {fn}", file=sys.stderr)
        return re.sub(r'\.[A-Z]+$', '', fn)
    except IndexError:
        print("signature not found", file=sys.stderr)
        return 'CERT'

run(f"(cd && mkdir t && cd t && unzip -q /out/{path})", shell=True)
sigfile = _sigfile()
run(f"(cd ~/t && rm -rf META-INF && zip -qr ~/app.apk . && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore /key/{keystorepath} -storepass android -keypass android -sigfile {sigfile} ~/app.apk androiddebugkey && rm -f /out/{outpath} && mv ~/app.apk /out/{outpath})", shell=True)
