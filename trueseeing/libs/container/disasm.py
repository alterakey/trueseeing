#!/usr/bin/env python3
import sqlite3
import glob
import subprocess
import os.path
import shutil
import sys
from typing import Tuple

apk, archive = sys.argv[1], sys.argv[2]

tmpdir = '/tmp'

os.chdir(tmpdir)
c = sqlite3.connect('archive.db')
with c:
    c.execute('pragma mmap_size=8589934592')
    c.execute('pragma synchronous=0')
    c.execute('drop table if exists files')
    c.execute('create table files(path text not null unique, blob bytes not null)')

with c:
    subprocess.run(f'java -jar /app/apktool.jar d --use-aapt2 -o files /out/{apk}', shell=True)
    os.chdir('files')
    def read_as_row(fn: str) -> Tuple[str, bytes]:
        with open(fn, 'rb') as f:
            return fn, f.read()
    c.executemany('insert into files (path, blob) values (?,?)', (read_as_row(fn) for fn in glob.glob('**', recursive=True) if os.path.isfile(fn)))
    c.commit()

os.chdir(tmpdir)
shutil.move('archive.db', os.path.join('/out', archive))
