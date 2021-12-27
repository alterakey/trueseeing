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

from __future__ import annotations
from typing import TYPE_CHECKING

import glob
import logging
import os
import re
import shutil
import tempfile

log = logging.getLogger(__name__)

class SigningKey:
  def key(self) -> str:
    path = os.path.join(os.environ['HOME'], '.android', 'debug.keystore')
    if os.path.exists(path):
      return path
    else:
      os.makedirs(os.path.dirname(path))
      log.info("generating key for repackaging")
      os.system('keytool -genkey -v -keystore %(path)s -alias androiddebugkey -dname "CN=Android Debug, O=Android, C=US" -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000' % dict(path=path))
      return path


class Unsigner:
  def __init__(self, apk: str, out: str) -> None:
    self.apk = os.path.realpath(apk)
    self.out = out

  def unsign(self) -> None:
    # XXX insecure
    with tempfile.TemporaryDirectory() as d:
      os.system("(mkdir -p %(root)s/t)" % dict(root=d, apk=self.apk))
      os.system("(cd %(root)s/t && unzip -q %(apk)s && rm -rf META-INF && zip -qr ../unsigned.apk .)" % dict(root=d, apk=self.apk))
      shutil.copyfile(os.path.join(d, 'unsigned.apk'), self.out)


class Resigner:
  def __init__(self, apk: str, out: str) -> None:
    self.apk = os.path.realpath(apk)
    self.out = out

  def resign(self) -> None:
    # XXX insecure
    with tempfile.TemporaryDirectory() as d:
      os.system("(mkdir -p %(root)s/t)" % dict(root=d, apk=self.apk))
      os.system("(cd %(root)s/t && unzip -q %(apk)s)" % dict(root=d, apk=self.apk))
      sigfile = self._sigfile(d)
      os.system("(cd %(root)s/t && rm -rf META-INF && zip -qr ../signed.apk .)" % dict(root=d, apk=self.apk))
      os.system(
        "(cd %(root)s && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore %(keystore)s -storepass android -keypass android -sigfile %(sigfile)s signed.apk androiddebugkey)" % dict(
          root=d, keystore=SigningKey().key(), sigfile=sigfile))
      shutil.copyfile(os.path.join(d, 'signed.apk'), self.out)

  def _sigfile(self, root: str) -> str:
    try:
      fn = [os.path.basename(fn) for fn in glob.glob("%(root)s/t/META-INF/*.SF" % dict(root=root))][0]
      log.debug("found existing signature: %s" % fn)
      return re.sub(r'\.[A-Z]+$', '', fn)
    except IndexError:
      log.debug("signature not found")
      return 'CERT'
