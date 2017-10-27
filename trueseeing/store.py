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

import re
import random
import hashlib
import os.path
import sqlite3
import itertools
import pkg_resources
import trueseeing.literalquery
import trueseeing.code.model

def _re_fn(expr, item):
  if item is not None:
    return re.compile(expr).search(item) is not None
  else:
    return False

class Store:
  def __init__(self, path):
    self.path = os.path.join(path, 'store.db')
    is_creating = not os.path.exists(self.path)
    self.db = sqlite3.connect(self.path)
    self.db.create_function("REGEXP", 2, _re_fn)
    trueseeing.literalquery.Store(self.db).stage0()
    if is_creating:
      trueseeing.literalquery.Store(self.db).stage1()

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    pass

  def op_finalize(self):
    trueseeing.literalquery.Store(self.db).stage2()

  def op_get(self, k):
    for t,v in self.db.execute('select t,v from ops where op=?', (k)):
      return Token(t, v)

  def op_append(self, op):
    unused_id = None
    for r in self.db.execute('select max(op) from ops'):
      if r[0] is not None:
        unused_id = r[0] + 1
      else:
        unused_id = 1
    vec = tuple([op] + op.p)
    for t, idx in zip(vec, range(len(vec))):
      t._idx = idx
      t._id = unused_id + idx
    self.db.executemany('insert into ops(op,t,v) values (?,?,?)', ((t._id, t.t, t.v) for t in vec))
    self.db.executemany('insert into ops_p(op, idx, p) values (?,?,?)', ((op._id, t._idx, t._id) for t in vec))

  def op_mark_method(self, ops, method):
    self.db.executemany('insert into ops_method(op,method) values (?,?)', ((str(o._id), str(method._id)) for o in ops))

  def op_mark_class(self, ops, class_, ignore_dupes=False):
    if not ignore_dupes:
      self.db.executemany('insert into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in ops))
    else:
      self.db.executemany('insert or ignore into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in ops))

  def query(self):
    return Query(self)

class Query:
  def __init__(self, store):
    self.db = store.db

  def reversed_insns_in_method(self, from_):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from ops_method where op<(select op from ops_p where p=:from_op) and method=(select method from ops_method where op=(select op from ops_p where p=:from_op))) order by op desc', dict(from_op=from_._id)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  @staticmethod
  def _cond_as_sql(param, t, v):
    cond = dict(cond='1')
    if t is not None or v is not None:
      cond.update(dict(cond=' and '.join(['t=:t' if t is not None else '1', 'v like :v' if v is not None else '1'])))
      param.update({p:q for p,q in dict(t=t, v=v).items() if q is not None})
    return cond, param

  def find_recent_in_method(self, from_, t, v):
    cond, param = self._cond_as_sql(dict(from_op=from_._id), t, v)
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select op from ops_method where op<=(select op from ops_p where p=:from_op) and method=(select method from ops_method where op=(select op from ops_p where p=:from_op))) and (%(cond)s) order by op desc' % cond, param):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def ops(self):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs'):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def invocations(self, pattern):
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join op_vecs using (op) where interests_invokes.v like \'%(insn)s%%\'%(regexp)s' % dict(insn=pattern.insn, regexp=' and target regexp \'%(expr)s\'' % dict(expr=pattern.value))):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def invocations_in_class(self, class_, pattern):
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join ops_class using (op) join op_vecs using (op) where class=(select class from ops_class where op=:class_) and interests_invokes.v like \'%(insn)s%%\'%(regexp)s' % dict(insn=pattern.insn, regexp=' and target regexp \'%(expr)s\'' % dict(expr=pattern.value)), dict(class_=class_._id)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def consts(self, pattern):
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_consts join op_vecs using (op) where interests_consts.v like \'%(insn)s%%\'%(regexp)s' % dict(insn=pattern.insn, regexp=' and target regexp \'%(expr)s\'' % dict(expr=pattern.value))):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def sputs(self, target):
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_sputs join op_vecs using (op) where target=:target', dict(target=target)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def iputs(self, target):
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_iputs join op_vecs using (op) where target=:target', dict(target=target)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def ops_of(self, insn):
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where v=:insn', dict(insn=insn)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def classes_has_method_named(self, pattern):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs join ops_method using (op) where op in (select class from methods_class join method_method_name using (method) where method_name regexp \'%(expr)s\')' % dict(expr=pattern)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def classes_extends_has_method_named(self, method, extends):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from classes_extends_name join methods_class using (class) join method_method_name using (method) where method_name regexp \'%(expr1)s\' and extends_name regexp \'%(expr2)s\')' % dict(expr1=method, expr2=extends)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def classes_implements_has_method_named(self, method, implements):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op in (select class from classes_implements_name join methods_class using (class) join method_method_name using (method) where method_name regexp \'%(expr1)s\' and implements_name regexp \'%(expr2)s\')' % dict(expr1=method, expr2=implements)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def qualname_of(self, op):
    for r in self.db.execute('select qualname from method_qualname join ops_method using (method) where op=:op', dict(op=op._id)):
      return r[0]

  def class_name_of(self, op):
    for r in self.db.execute('select class_name from class_class_name join ops_class using (class) where op=:op', dict(op=op._id)):
      return r[0]

  def callers_of(self, op):
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join op_vecs using (op) where target=(select qualname from method_qualname where method=(select method from ops_method where op=:op))', dict(op=op._id)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def callers_of_method_named(self, pattern):
    for r in self.db.execute('select op as _0, t as _1, op_vecs.v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from interests_invokes join op_vecs using (op) where target regexp \'%(expr)s\'' % dict(expr=pattern)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def methods_in_class(self, method_name, related_class_name):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from classes_extends_name left join classes_implements_name using (class) join methods_class using (class) join method_method_name using (method) join op_vecs on (method=op) where (extends_name like :class_pat or implements_name like :class_pat) and method_name like :method_pat', dict(class_pat='%%%s%%' % related_class_name, method_pat='%%%s%%' % method_name)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def related_classes(self, related_class_name):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from classes_extends_name left join classes_implements_name using (class) join op_vecs on (class=op) where (extends_name regexp :class_pat or implements_name regexp :class_pat)', dict(class_pat=related_class_name)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def matches_in_method(self, method, pattern):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from ops_method join op_vecs using (op) where method=(select method from ops_method where op=:from_op) and v like \'%(insn)s%%\'%(regexp)s' % dict(insn=pattern.insn, regexp=' and v2 regexp \'%(expr)s\'' % dict(expr=pattern.value)), dict(from_op=method._id)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def class_of_method(self, method):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where op=(select class from ops_class where op=:from_op)', dict(from_op=method._id)):
      return trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])
