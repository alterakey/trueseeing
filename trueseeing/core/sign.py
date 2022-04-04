# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <altakey@gmail.com>
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

import os
import shutil
import tempfile

from trueseeing.core.tools import invoke_passthru
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  pass

class SigningKey:
  async def key(self) -> str:
    path = os.path.join(os.environ['HOME'], '.android', 'debug.keystore')
    if os.path.exists(path):
      return path
    else:
      os.makedirs(os.path.dirname(path))
      ui.info("generating key for repackaging")
      await invoke_passthru(f'keytool -genkey -v -keystore {path} -alias androiddebugkey -dname "CN=Android Debug, O=Android, C=US" -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000')
      return path


class Unsigner:
  def __init__(self, apk: str, out: str) -> None:
    self.apk = os.path.realpath(apk)
    self.out = out

  async def unsign(self) -> None:
    # XXX insecure
    with tempfile.TemporaryDirectory() as d:
      await invoke_passthru(f"(mkdir -p {d}/t)")
      await invoke_passthru(f"(cd {d}/t && unzip -q {self.apk} && rm -rf META-INF && zip -qr ../unsigned.apk .)")
      shutil.copyfile(os.path.join(d, 'unsigned.apk'), self.out)


class Resigner:
  def __init__(self, apk: str, out: str) -> None:
    self.apk = os.path.realpath(apk)
    self.out = out

  async def resign(self) -> None:
    # XXX insecure
    with tempfile.TemporaryDirectory() as d:
      await invoke_passthru(f"(mkdir -p {d}/t)")
      await invoke_passthru(f"(cd {d}/t && unzip -q {self.apk})")
      sigfile = self._sigfile(d)
      await invoke_passthru(f"(cd {d}/t && rm -rf META-INF && zip -qr ../signed.apk .)")
      await invoke_passthru(
        f"(cd {d} && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore {await SigningKey().key()} -storepass android -keypass android -sigfile {sigfile} signed.apk androiddebugkey)"
      )
      await invoke_passthru(
        f"(cd {d} && zipalign -p 4 signed.apk aligned.apk && rm -f signed.apk)"
      )
      shutil.copyfile(os.path.join(d, 'aligned.apk'), self.out)

  def _sigfile(self, root: str) -> str:
    import re
    from glob import glob
    try:
      fn = [os.path.basename(fn) for fn in glob(f"{root}/t/META-INF/*.SF")][0]
      ui.debug(f"found existing signature: {fn}")
      return re.sub(r'\.[A-Z]+$', '', fn)
    except IndexError:
      ui.debug("signature not found")
      return 'CERT'
