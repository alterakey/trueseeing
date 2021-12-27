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

import re
import os
import subprocess

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
    me = sys.argv[0]
    if self._packages:
      for pkg in self._packages:
        if Grab(pkg).exploit():
          print(f'{me}: package saved: {pkg}.apk')
          return 0
      else:
        print(f'{me}: package not found')
        return 1
    else:
      print(f'{me}: listing packages')
      for p in sorted(Grab.list_()):
        print(p)
      return 0

def invoked(as_: str) -> str:
  return subprocess.run(as_, shell=True, check=True, stdout=subprocess.PIPE).stdout.decode('utf-8')

def invoke_tried(as_: str) -> Optional[str]:
  try:
    return invoked(as_)
  except subprocess.CalledProcessError:
    return None

def version_of_default_device() -> float:
  try:
    out = invoked("adb shell cat /system/build.prop")
    m = re.search(r'ro.build.version.release=(.+?)', out)
    if m:
      return float(m.group(1))
    else:
      return FALLBACK_VERSION
  except (ValueError, subprocess.CalledProcessError):
    return FALLBACK_VERSION

def path_from(package: str) -> Iterable[Tuple[str, str]]:
  version = version_of_default_device()
  if version >= 8.0:
    return path_from_dump(package)
  elif version >= 4.4:
    return path_from_multidex(package)
  else:
    return path_from_premultidex(package)

def path_from_premultidex(package: str) -> Iterable[Tuple[str, str]]:
  for i in range(1, 16):
    yield f'/data/app/{package}-{i}.apk', f'{package}.apk'

def path_from_multidex(package: str) -> Iterable[Tuple[str, str]]:
  for i in range(1, 16):
    yield f'/data/app/{package}-{i}/base.apk', f'{package}.apk'

def path_from_dump(package: str) -> Iterable[Tuple[str, str]]:
  out = invoked('adb shell pm dump "%s"' % package)
  m = re.search('codePath=(/data/app/%s-.+)' % package, out)
  if m:
    yield os.path.join(m.group(1), 'base.apk'), f'{package}.apk'
  else:
    raise RuntimeError('pm dump does not return codePath')

class Grab:
  package: str
  def __init__(self, package: str) -> None:
    self.package = package

  def exploit(self) -> bool:
    for from_, to_ in path_from(self.package):
      out = invoke_tried("adb pull %s %s 2>/dev/null" % (from_, to_))
      if out is not None:
        out = invoke_tried("adb shell 'cat %s 2>/dev/null' > %s" % (from_, to_))
        if out is not None and os.path.getsize(to_) > 0:
          return True
        else:
          return False
    return True

  @classmethod
  def list_(cls) -> Iterable[str]:
    out = invoked("adb shell pm list packages")
    return (l.replace('package:', '') for l in filter(None, out.split('\n')))
