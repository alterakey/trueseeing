# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-23 Takahiro Yoshimura <altakey@gmail.com>
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
from trueseeing.core.literalquery import StorePrep, Query

if TYPE_CHECKING:
  import sqlite3
  from typing import Optional, Any, Iterable, Set, Tuple, List, AnyStr
  from trueseeing.core.code.model import Op

class Store:
  db: sqlite3.Connection

  def __init__(self, path: str, exclude_packages: List[str] = []) -> None:
    self._path = path
    self._excludes = exclude_packages
    self.db = self._open_db()

  def _open_db(self) -> sqlite3.Connection:
    import os.path
    import sqlite3
    store_path = os.path.join(self._path, 'store.db')
    is_creating = not os.path.exists(store_path)
    o = sqlite3.connect(store_path)
    o.create_function("REGEXP", 2, Store._re_fn, deterministic=True)
    StorePrep(o).stage0()
    if is_creating:
      self.prepare_schema()
    return o

  def prepare_schema(self) -> None:
    StorePrep(self.db).stage1()

  @staticmethod
  def _re_fn(expr: AnyStr, item: Any) -> bool:
    if item is not None:
      return re.compile(expr).search(item) is not None
    else:
      return False

  def __enter__(self) -> Store:
    return self

  def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
    pass

  def op_finalize(self) -> None:
    StorePrep(self.db).stage2()

  def op_get(self, k: int) -> Optional[Op]:
    for t,v in self.db.execute('select t,v from ops where op=?', (k, )):
      return Op(t, v)
    return None

  def op_store_ops(self, ops: Iterable[Op], c: Any = None) -> None:
    if c is None: c = self.db
    c.executemany('insert into ops(op,idx,t,v) values (?,?,?,?)', ((t._id, t._idx, t.t, t.v) for t in ops))

  def op_count_ops(self, c: Any = None) -> int:
    if c is None: c = self.db
    for cnt, in c.execute('select count(1) from ops where idx=0'):
      return cnt # type: ignore[no-any-return]
    return 0

  def op_store_classmap(self, classmap: Set[Tuple[int, int]], c: Any = None) -> int:
    if c is None: c = self.db
    c.executemany('insert into ops_class(class,op) select ?,op from ops where op between ? and ?', ((start, start, end) for start, end in classmap))
    return len(classmap)

  def op_generate_methodmap(self, c: Any = None) -> int:
    if c is None: c = self.db
    detected_methods = 0
    c.execute("create table tmp1 (op int primary key)")
    c.execute("create table tmp2 (op int primary key)")
    c.execute("insert into tmp1 select op from ops where t='directive' and v='method'")
    c.execute("insert into tmp2 select a.op as op from ops as a left join ops as c on (a.op=c.op-c.idx) where a.t='directive' and a.v='end' and c.idx=1 and c.v='method'")
    c.execute('insert into ops_method(method,op) select mm.sop as method,ops.op from (select tmp1.op as sop,(select min(op) from tmp2 where op>tmp1.op) as eop from tmp1) as mm left join ops on (ops.op between mm.sop and mm.eop)')
    for cnt, in c.execute('select count(1) from tmp1'):
      detected_methods = cnt
    c.execute("drop table tmp1")
    c.execute("drop table tmp2")
    return detected_methods

  def query(self) -> Query:
    return Query(self)
