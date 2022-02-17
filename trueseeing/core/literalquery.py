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

import os.path
import pkg_resources

from trueseeing.core.code.model import Op

if TYPE_CHECKING:
  from typing import Any, Iterable, Tuple, Dict, Optional
  from trueseeing.core.store import Store
  from trueseeing.core.code.model import InvocationPattern

class StorePrep:
  def __init__(self, c: Any) -> None:
    self.c = c

  def stage0(self) -> None:
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'store.s.sql')), 'r', encoding='utf-8') as f:
      self.c.executescript(f.read())

  def stage1(self) -> None:
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'store.0.sql')), 'r', encoding='utf-8') as f:
      self.c.executescript(f.read())

  def stage2(self) -> None:
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'store.1.sql')), 'r', encoding='utf-8') as f:
      self.c.executescript(f.read())


class Query:
  def __init__(self, store: Store) -> None:
    self.db = store.db

  @staticmethod
  def _op_from_row(r: Tuple[Any, ...]) -> Op:
    return Op(r[1], r[2], [Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x + 3] for x in range(3, 30, 3)) if o[0] is not None], id_=r[0])

  def reversed_insns_in_method(self, from_: Op) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from ops_method where op<(select op from ops_p where p=:from_op) and method=(select method from ops_method where op=(select op from ops_p where p=:from_op))) order by op desc', dict(from_op=from_._id)):
      yield self._op_from_row(r)

  @staticmethod
  def _cond_as_sql(param: Dict[str, Any], t: Optional[str], v: Optional[str]) -> Tuple[Dict[str, str], Dict[str, Any]]:
    cond = dict(cond='1')
    if t is not None or v is not None:
      cond.update(dict(cond=' and '.join(['t=:t' if t is not None else '1', 'v like :v' if v is not None else '1'])))
      param.update({p:q for p,q in dict(t=t, v=v).items() if q is not None})
    return cond, param

  def find_recent_in_method(self, from_: Op, t: str, v: str) -> Iterable[Op]:
    cond, param = self._cond_as_sql(dict(from_op=from_._id), t, v)
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from ops_method where op<=(select op from ops_p where p=:from_op) and method=(select method from ops_method where op=(select op from ops_p where p=:from_op))) and ({cond}) order by op desc', param):
      yield self._op_from_row(r)

  def ops(self) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs'):
      yield self._op_from_row(r)

  def invocations(self, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join op_vecs using (op) where interests_invokes.v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\''):
      yield self._op_from_row(r)

  def invocations_in_class(self, class_: Op, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join ops_class using (op) join op_vecs using (op) where class=(select class from ops_class where op=:class_) and interests_invokes.v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\'', dict(class_=class_._id)):
      yield self._op_from_row(r)

  def consts(self, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_consts join op_vecs using (op) where interests_consts.v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\''):
      yield self._op_from_row(r)

  def consts_in_class(self, class_: Op, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_consts join op_class using (op) join op_vecs using (op) where class=(select class from ops_class where op=:class_) and interests_consts.v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\'', dict(class_=class_._id)):
      yield self._op_from_row(r)

  def consts_in_package(self, name: str, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_consts join ops_class using (op) join op_vecs using (op) where class in (select class from class_class_name where class_name like :pat) and interests_consts.v like \'{pattern.insn}%\' and target regexp \'{pattern.value}\'', dict(pat=self._get_smali_pattern_of_package(name))):
      yield self._op_from_row(r)

  def sputs(self, target: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_sputs join op_vecs using (op) where target=:target', dict(target=target)):
      yield self._op_from_row(r)

  def iputs(self, target: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_iputs join op_vecs using (op) where target=:target', dict(target=target)):
      yield self._op_from_row(r)

  def ops_of(self, insn: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where v=:insn', dict(insn=insn)):
      yield self._op_from_row(r)

  def classes_has_method_named(self, pattern: str) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs join ops_method using (op) where op in (select class from methods_class join method_method_name using (method) where method_name regexp \'{pattern}\')'):
      yield self._op_from_row(r)

  def classes_extends_has_method_named(self, method: str, extends: str) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from classes_extends_name join methods_class using (class) join method_method_name using (method) where method_name regexp \'{method}\' and extends_name regexp \'{extends}\')'):
      yield self._op_from_row(r)

  def classes_implements_has_method_named(self, method: str, implements: str) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from classes_implements_name join methods_class using (class) join method_method_name using (method) where method_name regexp \'{method}\' and implements_name regexp \'{implements}\')'):
      yield self._op_from_row(r)

  def qualname_of(self, op: Optional[Op]) -> Optional[str]:
    if op:
      for o, in self.db.execute('select qualname from method_qualname join ops_method using (method) where op=:op', dict(op=op._id)):
        return o # type: ignore[no-any-return]
    return None

  def class_name_of(self, op: Optional[Op]) -> Optional[str]:
    if op:
      for o, in self.db.execute('select class_name from class_class_name join ops_class using (class) where op=:op', dict(op=op._id)):
        return o # type: ignore[no-any-return]
    return None

  def _get_smali_pattern_of_package(self, name: str) -> str:
    return r'L{}/%'.format(name.replace('.', '/'))

  def classes_in_package_named(self, name: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from class_class_name join op_vecs on (class=op) where class_name like :pat', dict(pat=self._get_smali_pattern_of_package(name))):
      yield self._op_from_row(r)

  def method_call_target_of(self, op: Optional[Op]) -> Optional[str]:
    if op:
      for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join op_vecs using (op) where op=:op', dict(op=op._id)):
        return r[8] # type: ignore[no-any-return]
    return None

  def callers_of(self, op: Op) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join op_vecs using (op) where target=(select qualname from method_qualname where method=(select method from ops_method where op=:op))', dict(op=op._id)):
      yield self._op_from_row(r)

  def callers_of_method_named(self, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join op_vecs using (op) where target regexp \'{pattern}\''):
      yield self._op_from_row(r)

  def methods_in_class(self, method_name: str, related_class_name: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from classes_extends_name left join classes_implements_name using (class) join methods_class using (class) join method_method_name using (method) join op_vecs on (method=op) where (extends_name like :class_pat or implements_name like :class_pat) and method_name like :method_pat', dict(class_pat=f'%{related_class_name}%', method_pat=f'%{method_name}%')):
      yield self._op_from_row(r)

  def related_classes(self, related_class_name: str) -> Iterable[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from classes_extends_name left join classes_implements_name using (class) join op_vecs on (class=op) where (extends_name regexp :class_pat or implements_name regexp :class_pat)', dict(class_pat=related_class_name)):
      yield self._op_from_row(r)

  def matches_in_method(self, method: Op, pattern: InvocationPattern) -> Iterable[Op]:
    for r in self.db.execute(f'select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from ops_method join op_vecs using (op) where method=(select method from ops_method where op=:from_op) and v like \'{pattern.insn}%\' and v2 regexp \'{pattern.value}\'', dict(from_op=method._id)):
      yield self._op_from_row(r)

  def class_of_method(self, method: Op) -> Optional[Op]:
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op=(select class from ops_class where op=:from_op)', dict(from_op=method._id)):
      return self._op_from_row(r)
    return None
