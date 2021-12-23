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

import logging

from trueseeing.core.context import Context

if TYPE_CHECKING:
  from typing import List

log = logging.getLogger(__name__)

class FingerprintMode:
  _files: List[str]
  def __init__(self, files: List[str]) -> None:
    self._files = files

  def invoke(self) -> int:
    for f in self._files:
      print('%s: %s' % (f, Context(f).fingerprint_of()))
    return 0