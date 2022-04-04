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

if TYPE_CHECKING:
  from typing import List
  from trueseeing.core.context import Context

class PatchMode:
  _files: List[str]
  def __init__(self, files: List[str]):
    self._files = files

  async def invoke(self, mode: str) -> int:
    from trueseeing.core.patch import Patcher
    for f in self._files:
      if mode == 'all':
        await Patcher(f, os.path.basename(f).replace('.apk', '-patched.apk')).apply_multi([
          PatchDebuggable(),
          PatchBackupable(),
          PatchLoggers()
        ])
    return 0

class PatchDebuggable:
  def apply(self, context: Context) -> None:
    manifest = context.parsed_manifest()
    for e in manifest.xpath('.//application'):
      e.attrib['{http://schemas.android.com/apk/res/android}debuggable'] = "false"
    with open(os.path.join(context.wd, 'AndroidManifest.xml'), 'wb') as f:
      f.write(context.manifest_as_xml(manifest))

class PatchBackupable:
  def apply(self, context: Context) -> None:
    manifest = context.parsed_manifest()
    for e in manifest.xpath('.//application'):
      e.attrib['{http://schemas.android.com/apk/res/android}allowBackup'] = "false"
    with open(os.path.join(context.wd, 'AndroidManifest.xml'), 'wb') as f:
      f.write(context.manifest_as_xml(manifest))

class PatchLoggers:
  def apply(self, context: Context) -> None:
    import re
    for fn in context.disassembled_classes():
      with open(fn, 'r') as f:
        content = f.read()
      with open(fn, 'w') as f:
        stage0 = re.sub(r'^.*?invoke-static.*?Landroid/util/Log;->.*?\(.*?$', '', content, flags=re.MULTILINE)
        stage1 = re.sub(r'^.*?invoke-virtual.*?Ljava/io/Print(Writer|Stream);->.*?\(.*?$', '', stage0, flags=re.MULTILINE)
        f.write(stage1)
