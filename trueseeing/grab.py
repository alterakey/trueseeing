# grab.py: fairly robust APK grabber for Android
# Copyright (C) 2015-2016 Takahiro Yoshimura <altakey@gmail.com>.  All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
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
    for from_, to_ in path_from(sys.argv[1]):
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
