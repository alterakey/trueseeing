#!/usr/bin/env python3
from subprocess import run
import sys

path, outpath, keystorepath = sys.argv[1], sys.argv[2], sys.argv[3]

run(f"(cp -a /out/{path} ~/app.apk && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore /key/{keystorepath} -storepass android -keypass android -sigfile CERT ~/app.apk androiddebugkey && rm -f /out/{outpath} && mv ~/app.apk /out/{outpath})", shell=True)
