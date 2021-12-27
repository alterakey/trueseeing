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

import itertools
import re
import logging

if TYPE_CHECKING:
  from typing import Iterable, List, Mapping, Any, Optional, Reversible
  from trueseeing.core.store import Store
  from trueseeing.core.code.op import Op, Token

log = logging.getLogger(__name__)

class InvocationPattern:
  insn: str
  value: str
  i: Optional[int]
  def __init__(self, insn: str, value: str, i: Optional[int] = None) -> None:
    self.insn = insn
    self.value = value
    self.i = i

class CodeFlows:
  @staticmethod
  def callers_of(store: Store, method: Op) -> Iterable[Op]:
    yield from store.query().callers_of(method)

  @staticmethod
  def callstacks_of(store: Store, method: Op) -> Mapping[Op, Any]:
    o = dict()
    for m in CodeFlows.callers_of(store, method):
      o[m] = CodeFlows.callstacks_of(store, m)
    return o
