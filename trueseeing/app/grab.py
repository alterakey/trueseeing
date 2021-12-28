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
import sys

if TYPE_CHECKING:
  from typing import List, Iterable, TypeVar, Optional, Tuple
  T = TypeVar('T')

class GrabMode:
  _packages: List[str]
  def __init__(self, packages: List[str]) -> None:
    self._packages = packages

  def invoke(self) -> int:
    if self._packages:
      for pkg in self._packages:
        if Grab(pkg).exploit():
          print('%s: package saved: %s.apk' % (sys.argv[0], pkg))
          return 0
        else:
          print('%s: package not found' % sys.argv[0])
          return 1
    else:
      print('%s: listing packages' % sys.argv[0])
      for p in sorted(Grab(None).list_()):
        print(p)
      return 0


class ProcessError(Exception):
  pass

def listifyed(v: T) -> Iterable[T]:
  if not (isinstance(v, list) or isinstance(v, tuple)):
    return [v]
  else:
    return v

def invoked(as_: str, expected_codes: Optional[Iterable[int]]=None) -> Tuple[int, bytes, bytes]:
  expected_codes = (expected_codes)

  p = subprocess.Popen(as_, shell=True, stdout=subprocess.PIPE)
  out, err = p.communicate()
  code = p.wait()
  if expected_codes is None or code in listifyed(expected_codes):
    return (code, out, err)
  else:
    raise ProcessError("process exited with unexpected exit codes (%d): %s", code, as_)

def version_of_default_device() -> float:
  try:
    code, out, err = invoked("adb shell cat /system/build.prop", expected_codes=0)
    return float(re.search(r'ro.build.version.release=(.+?)', out.decode('utf-8')).group(1))
  except (ValueError, ProcessError):
    return 8.0

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
    yield '/data/app/%s-%d.apk' % (package, i), '%s.apk' % package

def path_from_multidex(package: str) -> Iterable[Tuple[str, str]]:
  for i in range(1, 16):
    yield '/data/app/%s-%d/base.apk' % (package, i), '%s.apk' % package

def path_from_dump(package: str) -> Iterable[Tuple[str, str]]:
  code, out, err = invoked('adb shell pm dump "%s"' % package, expected_codes=0)
  yield os.path.join(re.search('codePath=(/data/app/%s-.+)' % package, out.decode('utf-8')).group(1), 'base.apk'), '%s.apk' % package

class Grab:
  package: str
  def __init__(self, package: str) -> None:
    self.package = package

  def exploit(self) -> bool:
    import sys
    for from_, to_ in path_from(self.package):
      code, _, _ = invoked("adb pull %s %s 2>/dev/null" % (from_, to_))
      if code != 0:
        code, _, _ = invoked("adb shell 'cat %s 2>/dev/null' > %s" % (from_, to_))
      if code == 0 and os.path.getsize(to_) > 0:
        return True
    else:
      return False

  def list_(self) -> Iterable[str]:
    _, stdout, _ = invoked("adb shell pm list packages", expected_codes=0)
    return (l.replace('package:', '') for l in filter(None, stdout.decode().split('\n')))
