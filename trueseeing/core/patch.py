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

from trueseeing.core.sign import SigningKey
from trueseeing.core.context import Context
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Protocol

  class Patch(Protocol):
    def apply(self, context: Context) -> None: ...

class Patcher:
  def __init__(self, apk: str, out: str) -> None:
    self.apk = os.path.realpath(apk)
    self.out = out

  async def apply(self, patch: Patch) -> None:
    return await self.apply_multi([patch])

  async def apply_multi(self, patches: List[Patch]) -> None:
    from shutil import copyfile
    from tempfile import TemporaryDirectory
    from pkg_resources import resource_filename
    with Context(self.apk, []) as context:
      await context.analyze()
      ui.info(f"{self.apk} -> {context.wd}")
      for p in patches:
        p.apply(context)

      # XXX
      sigfile = 'CERT'

      # XXX insecure
      with TemporaryDirectory() as d:
        from trueseeing.core.tools import invoke_passthru
        await invoke_passthru("(mkdir -p {root}/)".format(root=d))
        await invoke_passthru("(cd {wd} && java -jar {apktool} b --use-aapt2 -o {root}/patched.apk .)".format(root=d, apktool=resource_filename(__name__, os.path.join('..', 'libs', 'apktool.jar')), wd=context.wd))
        await invoke_passthru("(cd {root} && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore {keystore} -storepass android -keypass android -sigfile {sigfile} patched.apk androiddebugkey)".format(root=d, keystore=await SigningKey().key(), sigfile=sigfile))
        await invoke_passthru("(cd {root} && zipalign -p 4 patched.apk aligned.apk && rm -f patched.apk)".format(root=d))
        copyfile(os.path.join(d, 'aligned.apk'), self.out)
