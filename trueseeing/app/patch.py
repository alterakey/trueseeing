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

if TYPE_CHECKING:
  from typing import List
  from trueseeing.core.context import Context

class PatchMode:
  _files: List[str]
  def __init__(self, files: List[str]):
    self._files = files

  async def invoke(self, mode: str, no_cache_mode: bool = False) -> int:
    from trueseeing.core.patch import Patcher
    for f in self._files:
      try:
        if mode == 'all':
          await Patcher(f, os.path.basename(f).replace('.apk', '-patched.apk')).apply_multi([
            PatchDebuggable(),
            PatchBackupable(),
            PatchLoggers()
          ])
      finally:
        if no_cache_mode:
          from trueseeing.core.context import Context
          Context(f, []).remove()

    return 0

class PatchDebuggable:
  def apply(self, context: Context) -> None:
    manifest = context.parsed_manifest(patched=True)
    for e in manifest.xpath('.//application'):
      e.attrib['{http://schemas.android.com/apk/res/android}debuggable'] = "false"
    with context.store().db as c:
      c.execute('replace into patches (path, blob) values (:path,:blob)', dict(path='AndroidManifest.xml', blob=context.manifest_as_xml(manifest)))

class PatchBackupable:
  def apply(self, context: Context) -> None:
    manifest = context.parsed_manifest(patched=True)
    for e in manifest.xpath('.//application'):
      e.attrib['{http://schemas.android.com/apk/res/android}allowBackup'] = "false"
    with context.store().db as c:
      c.execute('replace into patches (path, blob) values (:path,:blob)', dict(path='AndroidManifest.xml', blob=context.manifest_as_xml(manifest)))

class PatchLoggers:
  def apply(self, context: Context) -> None:
    import re
    with context.store().db as c:
      for fn, content in c.execute('select path, coalesce(B.blob, A.blob) as blob from files as A left join patches as B using (path) where path like :path', dict(path='smali/%.smali')):
        stage0 = re.sub(rb'^.*?invoke-static.*?Landroid/util/Log;->.*?\(.*?$', b'', content, flags=re.MULTILINE)
        stage1 = re.sub(rb'^.*?invoke-virtual.*?Ljava/io/Print(Writer|Stream);->.*?\(.*?$', b'', stage0, flags=re.MULTILINE)
        if content != stage1:
          c.execute('replace into patches (path, blob) values (:path,:blob)', dict(path=fn, blob=stage1))
