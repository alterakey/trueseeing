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
from shutil import copyfile

import docker

from trueseeing.core.sign import SigningKey
from trueseeing.core.context import Context
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Protocol, Any, Optional

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
    try:
      cli = docker.from_env()
    except docker.errors.DockerException:
      ui.warn('docker is not available; disassmebling directly')
      await self._build_without_container(context)
    else:
      if all(cli.images.list(x) for x in ['alterakey/trueseeing-apk', 'alterakey/trueseeing-apk-zipalign']):
        built: Optional[str] = None
        signed: Optional[str] = None
        try:
          built = await self._build_with_container_build(cli, context)
          if built:
            signed = await self._build_with_container_sign(cli, context, built)
            if signed:
              from trueseeing.core.sign import ZipAligner
              await ZipAligner(signed, self._outpath).align()
        finally:
          if built:
            try:
              os.remove(built)
            except OSError:
              pass
          if signed:
            try:
              os.remove(signed)
            except OSError:
              pass
      else:
        ui.warn('container not found (use --bootstrap to build it); patching directly')
        await self._build_without_container(context)

  async def _build_with_container_build(self, cli: Any, context: Context) -> Optional[str]:
    # XXX: insecure
    tmpfile = 'assembled.apk'

    con = cli.containers.run('alterakey/trueseeing-apk', command=['asm.py', tmpfile, 'store.db'], volumes={context.wd:dict(bind='/out')}, remove=True, detach=True)
    try:
      con.wait()
      return os.path.join(context.wd, tmpfile)
    except KeyboardInterrupt:
      try:
        con.kill()
      except docker.errors.APIError:
        pass
      else:
        raise
      return None

  async def _build_with_container_sign(self, cli: Any, context: Context, target: str) -> Optional[str]:
    # XXX: insecure
    tmpfile = 'signed.apk'

    # generate key
    storepath = await SigningKey().key()

    con = cli.containers.run('alterakey/trueseeing-apk', command=['sign.py', os.path.basename(target), tmpfile, os.path.basename(storepath)], volumes={context.wd:dict(bind='/out'),os.path.dirname(storepath):dict(bind='/key')}, remove=True, detach=True)
    try:
      con.wait()
      return os.path.join(context.wd, tmpfile)
    except KeyboardInterrupt:
      try:
        con.kill()
      except docker.errors.APIError:
        pass
      else:
        raise
      return None

  async def _build_without_container(self, context: Context) -> None:
    from tempfile import TemporaryDirectory
    from pkg_resources import resource_filename

    # XXX
    sigfile = 'CERT'

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
      await invoke_passthru("(mkdir -p {root}/files)".format(root=d))
      await invoke_passthru("(cd {root} && java -jar {apktool} b --use-aapt2 -o patched.apk files)".format(root=d, apktool=resource_filename(__name__, os.path.join('..', 'libs', 'container', 'apktool.jar'))))
      await invoke_passthru("(cd {root} && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore {keystore} -storepass android -keypass android -sigfile {sigfile} patched.apk androiddebugkey)".format(root=d, keystore=await SigningKey().key(), sigfile=sigfile))
      await invoke_passthru("(cd {root} && zipalign -p 4 patched.apk aligned.apk && rm -f patched.apk)".format(root=d))
      copyfile(os.path.join(d, 'aligned.apk'), self._outpath)
