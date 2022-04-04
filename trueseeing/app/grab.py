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

import re
import os
from trueseeing.core.tools import try_invoke, invoke, list_async
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Iterable, TypeVar, Tuple, AsyncIterable
  T = TypeVar('T')

FALLBACK_VERSION = 8.0

class GrabMode:
  _packages: List[str]
  def __init__(self, packages: List[str]) -> None:
    self._packages = packages

  async def invoke(self) -> int:
    if self._packages:
      for pkg in self._packages:
        if await Grab(pkg).exploit():
          ui.info(f'package saved: {pkg}.apk')
          return 0
      else:
        ui.fatal('package not found')
    else:
      ui.info('listing packages')
      for p in sorted(await list_async(Grab.get_package_list())):
        ui.stdout(p)
      return 0

class Grab:
  _target: str
  def __init__(self, target: str) -> None:
    self._target = target

  async def exploit(self) -> bool:
    async for from_, to_ in self._path_from(self._target):
      out = await try_invoke(f"adb pull {from_} {to_} 2>/dev/null")
      if out is None:
        out = await try_invoke(f"adb shell 'cat {from_} 2>/dev/null' > {to_}")
        if out is not None and os.path.getsize(to_) > 0:
          return True
        else:
          return False
    return True

  @classmethod
  async def get_package_list(cls) -> AsyncIterable[str]:
    out = await invoke("adb shell pm list packages")
    for l in filter(None, out.split('\n')):
      yield l.replace('package:', '')

  @classmethod
  async def _path_from(cls, package: str) -> AsyncIterable[Tuple[str, str]]:
    version = await cls._version_of_default_device()
    if version >= 8.0:
      async for t in cls._path_from_dump(package):
        yield t
    elif version >= 4.4:
      for t in cls._path_from_multidex(package):
        yield t
    else:
      for t in cls._path_from_premultidex(package):
        yield t

  @classmethod
  def _path_from_premultidex(cls, package: str) -> Iterable[Tuple[str, str]]:
    for i in range(1, 16):
      yield f'/data/app/{package}-{i}.apk', f'{package}.apk'

  @classmethod
  def _path_from_multidex(cls, package: str) -> Iterable[Tuple[str, str]]:
    for i in range(1, 16):
      yield f'/data/app/{package}-{i}/base.apk', f'{package}.apk'

  @classmethod
  async def _path_from_dump(cls, package: str) -> AsyncIterable[Tuple[str, str]]:
    out = await invoke(f'adb shell pm dump "{package}"')
    m = re.search(f'codePath=(/data/app/.*{package}-.+)', out)
    if m:
      yield os.path.join(m.group(1), 'base.apk'), f'{package}.apk'
    else:
      raise RuntimeError('pm dump does not return codePath')

  @classmethod
  async def _version_of_default_device(cls) -> float:
    out = await try_invoke("adb shell cat /system/build.prop")
    if out is None:
      return FALLBACK_VERSION
    m = re.search(r'ro.build.version.release=(.+?)', out)
    if m:
      try:
        return float(m.group(1))
      except ValueError:
        return FALLBACK_VERSION
    else:
      return FALLBACK_VERSION
