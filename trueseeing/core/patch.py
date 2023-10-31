# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-23 Takahiro Yoshimura <altakey@gmail.com>
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
from shutil import copyfile

from trueseeing.core.sign import SigningKey
from trueseeing.core.context import Context
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Protocol

  class Patch(Protocol):
    def apply(self, context: Context) -> None: ...

class Patcher:
  def __init__(self, apk: str, out: str) -> None:
    self._path = os.path.realpath(apk)
    self._outpath = os.path.realpath(out)

  async def apply(self, patch: Patch) -> None:
    return await self.apply_multi([patch])

  async def apply_multi(self, patches: List[Patch]) -> None:
    with Context(self._path, []) as context:
      await context.analyze()
      ui.info(f"{self._path} -> {context.wd}")
      for p in patches:
        p.apply(context)

      await self._build(context)

  async def _build(self, context: Context) -> None:
    from tempfile import TemporaryDirectory
    from pkg_resources import resource_filename

    # XXX insecure
    with TemporaryDirectory() as d:
      with context.store().db as c:
        cwd = os.getcwd()
        try:
          os.chdir(d)
          os.makedirs('files')
          os.chdir('files')
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
        finally:
          os.chdir(cwd)

      from trueseeing.core.tools import invoke_passthru
      await invoke_passthru('(cd {root} && java -jar {apkeditor} b -i files -o patched.apk && java -jar {apksigner} sign --ks {keystore} --ks-pass pass:android patched.apk && cp -a patched.apk {outpath})'.format(
        root=d,
        apkeditor=resource_filename(__name__, os.path.join('..', 'libs', 'apkeditor.jar')),
        apksigner=resource_filename(__name__, os.path.join('..', 'libs', 'apksigner.jar')),
        keystore=await SigningKey().key(),
        outpath=self._outpath,
      ))
      copyfile(os.path.join(d, 'patched.apk'), self._outpath)
      copyfile(os.path.join(d, 'patched.apk.idsig'), self._outpath + '.idsig')
