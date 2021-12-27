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
import attr

if TYPE_CHECKING:
  from typing import Optional, List

class Token:
  t: str
  v: str
  def __init__(self, t: str, v: str) -> None:
    self.t = t
    self.v = v

  def __repr__(self) -> str:
    return '<Token t={} v={}>'.format(self.t, self.v)

  def eq(self, t: str, v: str) -> bool:
    return (self.t, self.v) == (t, v)

class Op(Token):
  p: List[Op]
  _id: Optional[int] = None
  _idx: Optional[int] = None
  def __init__(self, t: str, v: str, p: Optional[List[Op]] = None, id_: Optional[int]=None):
    super().__init__(t, v)
    if p is not None:
      self.p = p
    else:
      self.p = []
    if id_ is not None:
      self._id = id_

  def __repr__(self) -> str:
    return '<Op t={} v={}, p={}>'.format(self.t, self.v, self.p)
