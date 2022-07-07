#!/usr/bin/env python3
import sqlite3
import os.path
import shutil
import sys
from subprocess import run

apk, archive = sys.argv[1], sys.argv[2]

tmpdir = '/tmp'

os.chdir(tmpdir)
os.makedirs('files')
os.chdir('files')
c = sqlite3.connect(os.path.join('/out', archive))
with c:
    c.execute('pragma mmap_size=8589934592')
    c.execute('pragma synchronous=0')
    for path, blob in c.execute('select path, blob from files'):
        dirname = os.path.dirname(path)
        if dirname:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(blob)
    for path, blob in c.execute('select path, blob from patches'):
        dirname = os.path.dirname(path)
        if dirname:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(blob)
    c.execute('delete from patches')
    c.commit()

os.chdir(tmpdir)
run('java -jar /app/apktool.jar b --use-aapt2 -o output.apk files', shell=True)
shutil.move('output.apk', os.path.join('/out', apk))
