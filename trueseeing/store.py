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
  return re.compile(expr).search(item) is not None

class Store:
  def __init__(self, path, mode='r'):
    if mode in 'rw':
      self.path = os.path.join(path, 'store.db')
      with open(self.path, mode) as _:
        pass
      self.db = sqlite3.connect(self.path)
      self.db.create_function("REGEXP", 2, _re_fn)
      trueseeing.literalquery.Store(self.db).stage0()
      if mode == 'w':
        trueseeing.literalquery.Store(self.db).stage1()
    else:
      raise ArgumentError('mode: %s' % mode)

  def __enter__(self):
    self.db.__enter__()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.db.__exit__(exc_type, exc_value, traceback)

  def op_finalize(self):
    trueseeing.literalquery.Store(self.db).stage2()

  def op_get(self, k):
    for t,v in self.db.execute('select t,v from ops where id=?', (k)):
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
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from (select ops.op from ops join ops_p on (ops_p.op=ops.op and idx=2) join ops as target on (ops_p.p=target.op) where ops.t=\'id\' and ops.v like \'%(insn)s%%\'%(regexp)s) as A join op_vecs using (op)' % dict(insn=pattern.insn, regexp=' and target.v regexp \'%(expr)s\'' % dict(expr=pattern.value))):
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

  def callers_of(self, op):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where t=\'id\' and v like \'invoke%%\' and coalesce(v2,v1)=(select qualname from method_qualname where method=(select method from ops_method where op=:op))', dict(op=op._id)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])

  def callers_of_method_named(self, pattern):
    for r in self.db.execute('select op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from op_vecs where t=\'id\' and v like \'invoke%%\' and coalesce(v2,v1) regexp \'%(expr)s\'' % dict(expr=pattern)):
      yield trueseeing.code.model.Op(r[1], r[2], [trueseeing.code.model.Op(o[1], o[2], [], id_=o[0]) for o in (r[x:x+3] for x in range(3,30,3)) if o[0] is not None], id_=r[0])
