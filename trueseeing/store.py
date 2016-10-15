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
      if mode == 'w':
        trueseeing.literalquery.Store(self.db).stage0()
    else:
      raise ArgumentError('mode: %s' % mode)

  def __enter__(self):
    self.db.__enter__()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.db.__exit__(exc_type, exc_value, traceback)

  def op_finalize(self):
    self.db.execute('analyze')
    trueseeing.literalquery.Store(self.db).stage1()

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
    self.db.executemany('insert into ops_p(op, idx, p) values (?,?,?)', ((op._id, t._idx, t._id) for t in vec[1:]))

  def op_param_append(self, op, p):
    for r in self.db.execute('select max(idx) from ops_p where op=?', (op._id,)):
      if r[0] is not None:
        p._idx = r[0] + 1
      else:
        p._idx = 1
    self.db.execute('insert into ops_p(op, idx, p) values (?,?,?)', (op._id, p._idx, p._id))

  def op_mark_method(self, ops, method):
    self.db.executemany('insert into ops_method(op,method) values (?,?)', ((str(o._id), str(method._id)) for o in itertools.chain(ops, *(o.p for o in ops))))

  def op_mark_class(self, ops, class_, ignore_dupes=False):
    if not ignore_dupes:
      self.db.executemany('insert into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in itertools.chain(ops, *(o.p for o in ops))))
    else:
      self.db.executemany('insert or ignore into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in itertools.chain(ops, *(o.p for o in ops))))

  def query(self):
    return Query(self)

class Query:
  def __init__(self, store):
    self.db = store.db

  def reversed_insns_in_method(self, from_):
    reg = []
    for r in self.db.execute('select ops.op as _0, ops.t as _1, ops.v as _2, ops_p.idx as _3 from ops join ops_method on (ops.op=ops_method.op) left outer join ops_p on (ops_p.p=ops.op) where method=(select method from ops_method where op=:from_op) and ops.op<=:from_op order by ops.op desc', dict(from_op=from_._id)):
      if r[3] is None:
        yield trueseeing.code.model.Op(r[1], r[2], reg, id_=r[0])
        reg = []
      else:
        idx = int(r[3])
        if len(reg) < idx:
          reg.extend([None] * (idx - len(reg)))
        reg[idx-1] = trueseeing.code.model.Op(r[1], r[2], [], id_=r[0])

  def invocations(self, pattern):
    return self.db.execute('select ops.op as _0, ops.v as _1, p2.v as _2 from ops join ops_p on (ops_p.op=ops.op and ops_p.idx=2) join ops as p2 on (ops_p.p=p2.op) where ops.t=\'id\' and ops.v like \'%(insn)s%%\'%(regexp)s' % dict(insn=pattern.insn, regexp=' and p2.v regexp \'%(expr)s\'' % dict(expr=pattern.value)))

  def invocation_in_class(self, class_, pattern):
    return self.db.execute('select ops.op as _0, ops.v as _1, p2.v as _2 from ops join ops_class on (ops.op=ops_class.op) join ops_p on (ops_p.op=ops.op and ops_p.idx=2) join ops as p2 on (ops_p.p=p2.op) where class=(select class from ops_class where op=:from_op) and ops.t=\'id\' and ops.v like \'%(insn)s%%\'%(regexp)s' % dict(insn=pattern.insn, regexp=' and p2.v regexp \'%(expr)s\'' % dict(expr=pattern.value)), dict(from_op=class_._id))

  def sput(self, from_, field):
    for r in self.db.execute('select ops.op as _0, ops.v as _1, p1.v as _2, p2.v as _3 from ops join ops_method on (ops.op=ops_method.op) join ops_p as pp1 on (pp1.op=ops.op and pp1.idx=1)  join ops_p as pp2 on (pp2.op=ops.op and pp2.idx=2) join ops as p1 on (pp1.p=p1.op) join ops as p2 on (pp2.p=p2.op) where method=(select method from ops_method where op=:from_op) and ops.op<=:from_op and ops.v like \'sput-%%\' and p2.v=:field order by _0 desc limit 1', dict(from_op=from_._id, field=field)):
      yield r
      return
    for r in self.db.execute('select ops.op as _0, ops.v as _1, p1.v as _2, p2.v as _3 from ops join ops_p as pp1 on (pp1.op=ops.op and pp1.idx=1)  join ops_p as pp2 on (pp2.op=ops.op and pp2.idx=2) join ops as p1 on (pp1.p=p1.op) join ops as p2 on (pp2.p=p2.op) where ops.v like \'sput-%%\' and p2.v=:field', dict(field=field)):
      yield r
      return
