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

import os
import shutil
import tempfile

import pkg_resources

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

  def apply(self, patch: Patch) -> None:
    return self.apply_multi([patch])

  def apply_multi(self, patches: List[Patch]) -> None:
    with Context(self.apk) as context:
      context.analyze()
      ui.info(f"{self.apk} -> {context.wd}")
      for p in patches:
          p.apply(context)

      # XXX
      sigfile = 'CERT'

      # XXX insecure
      with tempfile.TemporaryDirectory() as d:
        os.system("(mkdir -p {root}/)".format(root=d))
        os.system("(cd {wd} && java -jar {apktool} b -o {root}/patched.apk .)".format(root=d, apktool=pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'apktool.jar')), wd=context.wd))
        os.system("(cd {root} && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore {keystore} -storepass android -keypass android -sigfile {sigfile} patched.apk androiddebugkey)".format(root=d, keystore=SigningKey().key(), sigfile=sigfile))
        shutil.copyfile(os.path.join(d, 'patched.apk'), self.out)
