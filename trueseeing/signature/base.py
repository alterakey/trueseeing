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

import os
import re
import glob
import importlib
import pkg_resources

if TYPE_CHECKING:
  from typing import Type, Tuple, Any, Iterable, Optional
  from trueseeing.core.context import Context
  from trueseeing.core.issue import Issue

class Detector:
  option: Optional[str] = None
  description: Optional[str] = None

  def __init__(self, context: Context) -> None:
    self.context = context

  @classmethod
  def as_signature(cls: Type[Detector]) -> Tuple[Optional[str], Type[Detector]]:
    return (cls.option, cls)

  def detect(self) -> Iterable[Issue]:
    res = self.do_detect()
    if res is not None:
      yield from res
    else:
      yield from []

  def do_detect(self) -> Iterable[Issue]:
    pass

class SignatureDiscoverer:
  PRIORITY = ['fingerprint', 'manifest', 'security']

  def discovered(self) -> Iterable[str]:
    return sorted([os.path.basename(r).replace('.py', '') for r in
                   glob.glob(pkg_resources.resource_filename(__name__, os.path.join('*'))) if
                   re.match(r'^[^_].*\.py$', os.path.basename(r)) and not re.match(r'^base\.py$', os.path.basename(r))],
                  key=self.key)

  def key(self, k: str) -> int:
    try:
      return self.PRIORITY.index(k)
    except ValueError:
      return 31337

class SignatureClasses:
  @staticmethod
  def extracted() -> Iterable[Type[Detector]]:
    mods = [importlib.import_module('trueseeing.signature.%s' % s) for s in SignatureDiscoverer().discovered()]
    for m in mods:
      for attr in dir(m):
        i = getattr(m, attr)
        try:
          if issubclass(i, Detector) and i.option:
            yield i
        except TypeError:
          pass
