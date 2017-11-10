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

import glob
import os
import re
import tempfile
import logging
import shutil

import pkg_resources
import lxml.etree as ET

from trueseeing.context import Context

log = logging.getLogger(__name__)

class SigningKey:
  def __init__(self):
    pass
  def key(self):
    path = os.path.join(os.environ['HOME'], '.android', 'debug.keystore')
    if os.path.exists(path):
      return path
    else:
      os.makedirs(os.dirname(path))
      log.info("generating key for repackaging")
      os.system('keytool -genkey -v -keystore %(path)s -alias androiddebugkey -dname "CN=Android Debug, O=Android, C=US" -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000' % dict(path=path))
      return path

class Patches:
  def __init__(self, apk, out, chain):
    self.apk = os.path.realpath(apk)
    self.out = out
    self.chain = chain

  def apply(self):
    with Context() as context:
      context.analyze(self.apk)
      log.info("%s -> %s" % (self.apk, context.wd))
      for p in self.chain:
          p.patch(context)

      # XXX
      sigfile = 'CERT'

      # XXX insecure
      with tempfile.TemporaryDirectory() as d:
        os.system("(mkdir -p %(root)s/)" % dict(root=d, apk=self.apk))
        os.system("(cd %(wd)s && java -jar %(apktool)s b -o %(root)s/patched.apk .)" % dict(root=d, apktool=pkg_resources.resource_filename(__name__, os.path.join('libs', 'apktool.jar')), wd=context.wd))
        os.system("(cd %(root)s && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore %(keystore)s -storepass android -keypass android -sigfile %(sigfile)s patched.apk androiddebugkey)" % dict(root=d, keystore=SigningKey().key(), sigfile=sigfile))
        shutil.copyfile(os.path.join(d, 'patched.apk'), self.out)

class PatchDebuggable:
  def patch(self, context):
    manifest = context.parsed_manifest()
    for e in manifest.xpath('.//application'):
      e.attrib['{http://schemas.android.com/apk/res/android}debuggable'] = "false"
    with open(os.path.join(context.wd, 'AndroidManifest.xml'), 'wb') as f:
      f.write(ET.tostring(manifest))

class PatchBackupable:
  def patch(self, context):
    manifest = context.parsed_manifest()
    for e in manifest.xpath('.//application'):
      e.attrib['{http://schemas.android.com/apk/res/android}allowBackup'] = "false"
    with open(os.path.join(context.wd, 'AndroidManifest.xml'), 'wb') as f:
      f.write(ET.tostring(manifest))

class PatchLoggers:
  def patch(self, context):
    for fn in context.disassembled_classes():
      with open(fn, 'r') as f:
        content = f.read()
      with open(fn, 'w') as f:
        stage0 = re.sub(r'^.*?invoke-static.*?Landroid/util/Log;->.*?\(.*?$', '', content, flags=re.MULTILINE)
        stage1 = re.sub(r'^.*?invoke-virtual.*?Ljava/io/Print(Writer|Stream);->.*?\(.*?$', '', stage0, flags=re.MULTILINE)
        f.write(stage1)
