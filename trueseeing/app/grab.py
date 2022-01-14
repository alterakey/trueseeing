# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
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
from trueseeing.core.tools import try_invoke, invoke
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Iterable, TypeVar, Optional, Tuple
  T = TypeVar('T')

FALLBACK_VERSION = 8.0

class GrabMode:
  _packages: List[str]
  def __init__(self, packages: List[str]) -> None:
    self._packages = packages

  def invoke(self) -> int:
    import sys
    if self._packages:
      for pkg in self._packages:
        if Grab(pkg).exploit():
          ui.info(f'package saved: {pkg}.apk')
          return 0
      else:
        ui.fatal(f'package not found')
    else:
      ui.info(f'listing packages')
      for p in sorted(Grab.get_package_list()):
        ui.stdout(p)
      return 0


class Grab:
  _target: str
  def __init__(self, target: str) -> None:
    self._target = target

  def exploit(self) -> bool:
    for from_, to_ in self._path_from(self._target):
      out = try_invoke(f"adb pull {from_} {to_} 2>/dev/null")
      if out is None:
        out = try_invoke(f"adb shell 'cat {from_} 2>/dev/null' > {to_}")
        if out is not None and os.path.getsize(to_) > 0:
          return True
        else:
          return False
    return True

  @classmethod
  def get_package_list(cls) -> Iterable[str]:
    out = invoke("adb shell pm list packages")
    return (l.replace('package:', '') for l in filter(None, out.split('\n')))

  @classmethod
  def _path_from(cls, package: str) -> Iterable[Tuple[str, str]]:
    version = cls._version_of_default_device()
    if version >= 8.0:
      return cls._path_from_dump(package)
    elif version >= 4.4:
      return cls._path_from_multidex(package)
    else:
      return cls._path_from_premultidex(package)

  @classmethod
  def _path_from_premultidex(cls, package: str) -> Iterable[Tuple[str, str]]:
    for i in range(1, 16):
      yield f'/data/app/{package}-{i}.apk', f'{package}.apk'

  @classmethod
  def _path_from_multidex(cls, package: str) -> Iterable[Tuple[str, str]]:
    for i in range(1, 16):
      yield f'/data/app/{package}-{i}/base.apk', f'{package}.apk'

  @classmethod
  def _path_from_dump(cls, package: str) -> Iterable[Tuple[str, str]]:
    out = invoke(f'adb shell pm dump "{package}"')
    m = re.search(f'codePath=(/data/app/.*{package}-.+)', out)
    if m:
      yield os.path.join(m.group(1), 'base.apk'), f'{package}.apk'
    else:
      raise RuntimeError('pm dump does not return codePath')

  @classmethod
  def _version_of_default_device(cls) -> float:
    out = try_invoke("adb shell cat /system/build.prop")
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
