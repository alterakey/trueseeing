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

import os
import re
import glob
import importlib
import pkg_resources
import math

class Detector:
  option = None
  description = None

  def __init__(self, context):
    self.context = context

  @classmethod
  def as_signature(cls):
    return (cls.option, cls)

  def detect(self):
    res = self.do_detect()
    if res is not None:
      yield from res
    else:
      yield from []

  def do_detect(self):
    pass

class SignatureDiscoverer:
  PRIORITY = ['fingerprint', 'manifest', 'security']

  def __init__(self):
    pass

  def discovered(self):
    return sorted([os.path.basename(r).replace('.py', '') for r in glob.glob(pkg_resources.resource_filename(__name__, os.path.join('*'))) if re.match(r'^[^_].*\.py$', os.path.basename(r)) and not re.match('^base.py$', os.path.basename(r))], key=self.key)

  def key(self, k):
    try:
      return self.PRIORITY.index(k)
    except ValueError:
      return 31337

class SignatureClasses:
  def __init__(self):
    pass

  def extracted(self):
    mods = [importlib.import_module('trueseeing.signature.%s' % s) for s in SignatureDiscoverer().discovered()]
    for m in mods:
      for attr in dir(m):
        i = getattr(m, attr)
        try:
          if issubclass(i, Detector) and i.option:
            yield i
        except TypeError:
          pass
