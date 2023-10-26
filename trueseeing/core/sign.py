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
import shutil
import tempfile

from trueseeing.core.tools import invoke_passthru
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  pass

class SigningKey:
  _path: str

  def __init__(self) -> None:
    self._path = os.path.join(os.environ.get('TS2_HOME', os.path.join(os.environ['HOME'], '.trueseeing2')), 'sign.keystore')

  async def key(self) -> str:
    os.makedirs(os.path.dirname(self._path), exist_ok=True)
    if not os.path.exists(self._path):
      await self._generate()
    return self._path

  async def _generate(self) -> None:
    ui.info("generating key for repackaging")
    await invoke_passthru(f'keytool -genkey -v -keystore {self._path} -alias androiddebugkey -dname "CN=Android Debug, O=Android, C=US" -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000')

class Unsigner:
  _path: str
  _outpath: str

  def __init__(self, path: str, outpath: str):
    self._path = os.path.realpath(path)
    self._outpath = os.path.realpath(outpath)

  async def unsign(self) -> None:
    with tempfile.TemporaryDirectory() as d:
      await invoke_passthru(f"(mkdir -p {d}/t)")
      await invoke_passthru(f"(cd {d}/t && unzip -q {self._path} && rm -rf META-INF && zip -qr ../unsigned.apk .)")
      shutil.copyfile(os.path.join(d, 'unsigned.apk'), self._outpath)


class Resigner:
  _path: str
  _outpath: str

  def __init__(self, path: str, outpath: str):
    self._path = os.path.realpath(path)
    self._outpath = os.path.realpath(outpath)

  async def resign(self) -> None:
    from pkg_resources import resource_filename
    with tempfile.TemporaryDirectory() as d:
      await invoke_passthru(
        "java -jar {apksigner} sign --ks {ks} --ks-pass pass:android --in {path} --out {d}/signed.apk".format(
          d=d,
          apksigner=resource_filename(__name__, os.path.join('..', 'libs', 'apksigner.jar')),
          ks=await SigningKey().key(),
          path=self._path,
        )
      )
      shutil.copyfile(os.path.join(d, 'signed.apk'), self._outpath)
      shutil.copyfile(os.path.join(d, 'signed.apk.idsig'), self._outpath.replace('.apk', '.apk.idsig'))
