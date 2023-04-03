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

import docker

from trueseeing.core.tools import invoke_passthru
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Any, Optional

class SigningKey:
  _path: str

  def __init__(self) -> None:
    self._path = os.path.join(os.environ['HOME'], '.trueseeing2', 'sign.keystore')

  async def key(self) -> str:
    os.makedirs(os.path.dirname(self._path), exist_ok=True)
    if not os.path.exists(self._path):
      await self._generate()
    return self._path

  async def _generate(self) -> None:
    try:
      cli = docker.from_env()
    except docker.errors.DockerException:
      ui.warn('docker is not available; disassmebling directly')
      await self._do_without_container()
    else:
      if cli.images.list('alterakey/trueseeing-apk'):
        self._do_with_container(cli)
      else:
        ui.warn('container not found (use --bootstrap to build it); generating keystore directly')
        await self._do_without_container()

  def _do_with_container(self, cli: Any) -> None:
    con = cli.containers.run('alterakey/trueseeing-apk', command=['genkey.py', 'sign.keystore'], volumes={os.path.dirname(self._path):dict(bind='/out')}, remove=True, detach=True)
    try:
      con.wait()
    except KeyboardInterrupt:
      try:
        con.kill()
      except docker.errors.APIError:
        pass
      else:
        raise

  async def _do_without_container(self) -> None:
    ui.info("generating key for repackaging")
    await invoke_passthru(f'keytool -genkey -v -keystore {self._path} -alias androiddebugkey -dname "CN=Android Debug, O=Android, C=US" -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000')

class ZipAligner:
  _path: str
  _outpath: str

  def __init__(self, path: str, outpath: str):
    self._path = os.path.realpath(path)
    self._outpath = os.path.realpath(outpath)

  async def align(self) -> None:
    try:
      cli = docker.from_env()
    except docker.errors.DockerException:
      ui.warn('docker is not available; disassmebling directly')
      await self._do_without_container()
    else:
      if cli.images.list('alterakey/trueseeing-apk-zipalign'):
        self._do_with_container(cli)
      else:
        ui.warn('container not found (use --bootstrap to build it); zipaligning directly')
        await self._do_without_container()

  def _do_with_container(self, cli: Any) -> None:
    tmpfile = 'aligned.apk'
    con = cli.containers.run('alterakey/trueseeing-apk-zipalign', command=['-fp', '4', os.path.basename(self._path), tmpfile], volumes={os.path.dirname(self._path):dict(bind='/out')}, remove=True, detach=True)
    try:
      con.wait()
      shutil.move(os.path.join(os.path.dirname(self._path), tmpfile), self._outpath)
    except KeyboardInterrupt:
      try:
        con.kill()
      except docker.errors.APIError:
        pass
      else:
        raise

  async def _do_without_container(self) -> None:
    await invoke_passthru(f'rm -f {self._outpath} && zipalign -p 4 {self._path} {self._outpath}')

class Unsigner:
  _path: str
  _outpath: str

  def __init__(self, path: str, outpath: str):
    self._path = os.path.realpath(path)
    self._outpath = os.path.realpath(outpath)

  async def unsign(self) -> None:
    try:
      cli = docker.from_env()
    except docker.errors.DockerException:
      ui.warn('docker is not available; disassmebling directly')
      await self._do_without_container()
    else:
      if cli.images.list('alterakey/trueseeing-apk'):
        self._do_with_container(cli)
      else:
        ui.warn('container not found (use --bootstrap to build it); unsigning directly')
        await self._do_without_container()

  def _do_with_container(self, cli: Any) -> None:
    tmpfile = 'unsigned.apk'
    con = cli.containers.run('alterakey/trueseeing-apk', command=['unsign.py', os.path.basename(self._path), tmpfile], volumes={os.path.dirname(self._path):dict(bind='/out')}, remove=True, detach=True)
    try:
      con.wait()
      shutil.move(os.path.join(os.path.dirname(self._path), tmpfile), self._outpath)
    except KeyboardInterrupt:
      try:
        con.kill()
      except docker.errors.APIError:
        pass
      else:
        raise

  async def _do_without_container(self) -> None:
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
    try:
      cli = docker.from_env()
    except docker.errors.DockerException:
      ui.warn('docker is not available; disassmebling directly')
      await self._do_without_container()
    else:
      if cli.images.list('alterakey/trueseeing-apk'):
        signed_but_aligned = await self._do_with_container_resign_only(cli)
        if signed_but_aligned:
          try:
            await ZipAligner(signed_but_aligned, self._outpath).align()
          finally:
            os.remove(signed_but_aligned)
      else:
        ui.warn('container not found (use --bootstrap to build it); unsigning directly')
        await self._do_without_container()

  async def _do_with_container_resign_only(self, cli: Any) -> Optional[str]:
    # XXX: insecure
    tmpfile = 'to-align.apk'

    # generate key
    storepath = await SigningKey().key()

    con = cli.containers.run('alterakey/trueseeing-apk', command=['resign.py', os.path.basename(self._path), tmpfile, os.path.basename(storepath)], volumes={os.path.dirname(self._path):dict(bind='/out'),os.path.dirname(storepath):dict(bind='/key')}, remove=True, detach=True)
    try:
      con.wait()
      return os.path.join(os.path.dirname(self._path), tmpfile)
    except KeyboardInterrupt:
      try:
        con.kill()
      except docker.errors.APIError:
        pass
      else:
        raise
      return None

  async def _do_without_container(self) -> None:
    with tempfile.TemporaryDirectory() as d:
      await invoke_passthru(f"(mkdir -p {d}/t)")
      await invoke_passthru(f"(cd {d}/t && unzip -q {self._path})")
      sigfile = self._sigfile(d)
      await invoke_passthru(f"(cd {d}/t && rm -rf META-INF && zip -qr ../signed.apk .)")
      await invoke_passthru(
        f"(cd {d} && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore {await SigningKey().key()} -storepass android -keypass android -sigfile {sigfile} signed.apk androiddebugkey)"
      )
      await invoke_passthru(
        f"(cd {d} && zipalign -p 4 signed.apk aligned.apk && rm -f signed.apk)"
      )
      shutil.copyfile(os.path.join(d, 'aligned.apk'), self._outpath)

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
