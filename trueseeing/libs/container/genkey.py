#!/usr/bin/env python3
import subprocess
import sys

path = sys.argv[1]

print("generating key for repackaging")
subprocess.call(f'keytool -genkey -v -keystore {path} -alias androiddebugkey -dname "CN=Android Debug, O=Android, C=US" -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000', shell=True)
