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

import re
import os
import subprocess

class ProcessError(Exception):
  pass

def listifyed(v):
  if not (isinstance(v, list) or isinstance(v, tuple)):
    return [v]
  else:
    return v

def invoked(as_, expected_codes=None):
  expected_codes = (expected_codes)

  p = subprocess.Popen(as_, shell=True, stdout=subprocess.PIPE)
  out, err = p.communicate()
  code = p.wait()
  if expected_codes is None or code in listifyed(expected_codes):
    return (code, out, err)
  else:
    raise ProcessError("process exited with unexpected exit codes (%d): %s", code, as_)

def version_of_default_device():
  code, out, err = invoked("adb shell cat /system/build.prop", expected_codes=0)
  try:
    return float(re.search(r'ro.build.version.release=(.+?)', out.decode('utf-8')).group(1))
  except ValueError:
    return 7.0

def path_from(package):
  if version_of_default_device() >= 4.4:
    return path_from_multidex(package)
  else:
    return path_from_premultidex(package)

def path_from_premultidex(package):
  for i in range(1, 16):
    yield '/data/app/%s-%d.apk' % (package, i), '%s.apk' % package

def path_from_multidex(package):
  for i in range(1, 16):
    yield '/data/app/%s-%d/base.apk' % (package, i), '%s.apk' % package

class Grab:
  def __init__(self, package):
    self.package = package

  def exploit(self):
    import sys
    for from_, to_ in path_from(self.package):
      code, _, _ = invoked("adb pull %s %s 2>/dev/null" % (from_, to_))
      if code != 0:
        code, _, _ = invoked("adb shell 'cat %s 2>/dev/null' > %s" % (from_, to_))
      if code == 0 and os.path.getsize(to_) > 0:
        return True
    else:
      return False

  def list_(self):
    _, stdout, _ = invoked("adb shell pm list packages", expected_codes=0)
    return (l.replace('package:', '') for l in filter(None, stdout.decode().split('\n')))
