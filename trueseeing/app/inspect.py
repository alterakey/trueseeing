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

from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List

class InspectMode:
  _files: List[str]
  def __init__(self, files: List[str]) -> None:
    self._files = files

  def invoke(self) -> int:
    assert self._files
    from trueseeing.core.context import Context

    f = self._files[0]
    with Context(f, []) as context:
      ui.info(f"inspection mode; analyzing {f}")
      context.analyze()
      ui.info("analyzed, context in 'context'")
      from IPython import embed
      embed()
      return 0
