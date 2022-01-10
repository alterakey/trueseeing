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
import os.path
import sqlite3
import trueseeing.core.literalquery
import trueseeing.core.code.model
from trueseeing.core.literalquery import Query

if TYPE_CHECKING:
  from typing import Optional, List, Any
  from trueseeing.core.code.model import Op, Token

class Store:
  def __init__(self, path: str) -> None:
    self.path = os.path.join(path, 'store.db')
    is_creating = not os.path.exists(self.path)
    self.db = sqlite3.connect(self.path)
    self.db.create_function("REGEXP", 2, Store._re_fn)
    trueseeing.core.literalquery.StorePrep(self.db).stage0()
    if is_creating:
      trueseeing.core.literalquery.StorePrep(self.db).stage1()

  @staticmethod
  def _re_fn(expr: str, item: Any) -> bool:
    if item is not None:
      return re.compile(expr).search(item) is not None
    else:
      return False

  def __enter__(self) -> Store:
    return self

  def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
    pass

  def op_finalize(self) -> None:
    trueseeing.core.literalquery.StorePrep(self.db).stage2()

  def op_get(self, k: int) -> Optional[Op]:
    for t,v in self.db.execute('select t,v from ops where op=?', (k, )):
      return Op(t, v)
    return None

  def op_append(self, op: Op) -> None:
    unused_id: Optional[int] = None
    for r in self.db.execute('select max(op) from ops'):
      if r[0] is not None:
        unused_id = r[0] + 1
      else:
        unused_id = 1
    assert unused_id is not None

    vec = tuple([op] + op.p)
    for t, idx in zip(vec, range(len(vec))):
      t._idx = idx
      t._id = unused_id + idx
    self.db.executemany('insert into ops(op,t,v) values (?,?,?)', ((t._id, t.t, t.v) for t in vec))
    self.db.executemany('insert into ops_p(op, idx, p) values (?,?,?)', ((op._id, t._idx, t._id) for t in vec))

  def op_mark_method(self, ops: List[Op], method: Op) -> None:
    self.db.executemany('insert into ops_method(op,method) values (?,?)', ((str(o._id), str(method._id)) for o in ops))

  def op_mark_class(self, ops: List[Op], class_: Op, ignore_dupes: bool = False) -> None:
    if not ignore_dupes:
      self.db.executemany('insert into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in ops))
    else:
      self.db.executemany('insert or ignore into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in ops))

  def query(self) -> Query:
    return Query(self)
