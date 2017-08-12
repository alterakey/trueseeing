# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import tempfile
import os
import lxml.etree as ET
import shutil
import pkg_resources
import hashlib
import zipfile
import itertools
import glob
import sys
import subprocess

import trueseeing.code.parse
import trueseeing.store

class Context:
  def __init__(self):
    self.notes = []
    self.apk = None
    self.wd = None
    self.state = {}

  def workdir_of(self, apk):
    hashed = self.fingerprint_of(apk)
    dirname = os.path.join(os.environ['HOME'], '.trueseeing2', hashed[:2], hashed[2:4], hashed[4:])
    return dirname

  def store(self):
    assert self.wd is not None
    return trueseeing.store.Store(self.wd)

  def fingerprint(self):
    return fingerprint_of(self.apk)

  def fingerprint_of(self, apk):
    with zipfile.ZipFile(apk, 'r') as f:
      return hashlib.sha256(f.open('META-INF/MANIFEST.MF').read()).hexdigest()

  def analyze(self, apk, skip_resources=False):
    if self.wd is None:
      self.apk = apk
      self.wd = self.workdir_of(apk)
      try:
        if not os.path.exists(os.path.join(self.wd, '.done')):
          if os.path.exists(self.wd):
            sys.stderr.write('analyze: removing leftover\n')
            sys.stderr.flush()
            shutil.rmtree(self.wd)

          sys.stderr.write('\ranalyze: disassembling... ')
          sys.stderr.flush()
          os.makedirs(self.wd, mode=0o700)
          if not os.path.exists(os.path.join(self.wd, 'target.apk')):
            shutil.copyfile(self.apk, os.path.join(self.wd, 'target.apk'))
          # XXX insecure
          subprocess.run("java -jar %(apktool)s d -f %(skipresflag)s -o %(wd)s %(apk)s" % dict(apktool=pkg_resources.resource_filename(__name__, os.path.join('libs', 'apktool.jar')), wd=self.wd, apk=self.apk, skipresflag=('-r' if skip_resources else '')), shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          trueseeing.code.parse.SmaliAnalyzer(self.store()).analyze(open(fn, 'r', encoding='utf-8') for fn in self.disassembled_classes())
          with open(os.path.join(self.wd, '.done'), 'w'):
            pass
          sys.stderr.write('\ranalyze: disassembling... done.\n')
          sys.stderr.flush()
      finally:
        if os.path.exists(self.wd) and not os.path.exists(os.path.join(self.wd, 'target.apk')):
          shutil.copyfile(self.apk, os.path.join(self.wd, 'target.apk'))

    else:
      raise ValueError('analyzed once')

  def parsed_manifest(self):
    with open(os.path.join(self.wd, 'AndroidManifest.xml'), 'rb') as f:
      return ET.parse(f, parser=ET.XMLParser(recover=True))

  def disassembled_classes(self):
    try:
      return self.state['ts2.context.disassembled_classes']
    except KeyError:
      self.state['ts2.context.disassembled_classes'] = []
      for root, dirs, files in itertools.chain(*(os.walk(p) for p in glob.glob(os.path.join(self.wd, 'smali*/')))):
        self.state['ts2.context.disassembled_classes'].extend(os.path.join(root, f) for f in files if f.endswith('.smali'))
      return self.disassembled_classes()

  def disassembled_resources(self):
    try:
      return self.state['ts2.context.disassembled_resources']
    except KeyError:
      self.state['ts2.context.disassembled_resources'] = []
      for root, dirs, files in os.walk(os.path.join(self.wd, 'res')):
        self.state['ts2.context.disassembled_resources'].extend(os.path.join(root, f) for f in files if f.endswith('.xml'))
      return self.disassembled_resources()

  def disassembled_assets(self):
    try:
      return self.state['ts2.context.disassembled_assets']
    except KeyError:
      self.state['ts2.context.disassembled_assets'] = []
      for root, dirs, files in os.walk(os.path.join(self.wd, 'assets')):
        self.state['ts2.context.disassembled_assets'].extend(os.path.join(root, f) for f in files)
      return self.disassembled_assets()

  def source_name_of_disassembled_class(self, fn):
    return os.path.join(*os.path.relpath(fn, self.wd).split(os.sep)[1:])

  def dalvik_type_of_disassembled_class(self, fn):
    return 'L%s;' % (self.source_name_of_disassembled_class(fn).replace('.smali', ''))

  def source_name_of_disassembled_resource(self, fn):
    return os.path.relpath(fn, os.path.join(self.wd, 'res'))

  def class_name_of_dalvik_class_type(self, dc):
    return re.sub(r'^L|;$', '', dc).replace('/', '.')

  def permissions_declared(self):
    yield from self.parsed_manifest().getroot().xpath('//uses-permission/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android'))

  def string_resource_files(self):
    try:
      return self.state['ts2.context.string_resource_files']
    except KeyError:
      self.state['ts2.context.string_resource_files'] = []
      for root, dirs, files in os.walk(os.path.join(self.wd, 'res', 'values')):
        self.state['ts2.context.string_resource_files'].extend(os.path.join(root, f) for f in files if 'strings' in f)
      return self.string_resource_files()

  def string_resources(self):
    for fn in self.string_resource_files():
      with open(fn, 'rb') as f:
        yield from ((c.attrib['name'], c.text) for c in ET.parse(f, parser=ET.XMLParser(recover=True)).getroot().xpath('//resources/string') if c.text)

  def __enter__(self):
    return self

  def __exit__(self, *exc_details):
    pass
