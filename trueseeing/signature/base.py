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

from abc import ABC, abstractmethod

if TYPE_CHECKING:
  from typing import ClassVar
  from trueseeing.core.context import Context

class Detector(ABC):
  option: ClassVar[str]
  description: ClassVar[str]

  _context: Context

  def __init__(self, context: Context) -> None:
    self._context = context

  @abstractmethod
  async def detect(self) -> None: ...
