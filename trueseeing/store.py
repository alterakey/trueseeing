import random
import hashlib
import os.path
import sqlite3
import itertools

class Store:
  def __init__(self, path):
    self.db = sqlite3.connect(os.path.join(path, 'store.db'))
    for s in [
        'pragma journal_mode=WAL',
        'create table if not exists ops (op integer primary key, t varchar not null, v varchar not null)',
        'create table if not exists ops_p (op integer not null, idx integer not null, p integer not null)',
        'create table if not exists ops_method (op integer primary key, method integer not null)',
        'create table if not exists ops_class (op integer primary key, class integer not null)',
        'create index ops_method_method on ops_method (method)',
        'create index ops_class_class on ops_class (class)',
        'create index ops_p_op on ops_p (op)',
        '''\
create view op_vecs as
  select
    ops.op as op, ops.t as t, ops.v as v,
    ops1.op as op1, ops1.t as t1, ops1.v as v1,
    ops2.op as op2, ops2.t as t2, ops2.v as v2,
    ops3.op as op3, ops3.t as t3, ops3.v as v3,
    ops4.op as op4, ops4.t as t4, ops4.v as v4,
    ops5.op as op5, ops5.t as t5, ops5.v as v5,
    ops6.op as op6, ops6.t as t6, ops6.v as v6,
    ops7.op as op7, ops7.t as t7, ops7.v as v7,
    ops8.op as op8, ops8.t as t8, ops8.v as v8,
    ops9.op as op9, ops9.t as t9, ops9.v as v9,
    opsa.op as opa, opsa.t as ta, opsa.v as va
  from
    ops
      left join ops_p as ops_p1 on (ops.op=ops_p1.op and ops_p1.idx=1)
      left join ops_p as ops_p2 on (ops.op=ops_p2.op and ops_p2.idx=2)
      left join ops_p as ops_p3 on (ops.op=ops_p3.op and ops_p3.idx=3)
      left join ops_p as ops_p4 on (ops.op=ops_p4.op and ops_p4.idx=4)
      left join ops_p as ops_p5 on (ops.op=ops_p5.op and ops_p5.idx=5)
      left join ops_p as ops_p6 on (ops.op=ops_p6.op and ops_p6.idx=6)
      left join ops_p as ops_p7 on (ops.op=ops_p7.op and ops_p7.idx=7)
      left join ops_p as ops_p8 on (ops.op=ops_p8.op and ops_p8.idx=8)
      left join ops_p as ops_p9 on (ops.op=ops_p9.op and ops_p9.idx=9)
      left join ops_p as ops_pa on (ops.op=ops_pa.op and ops_pa.idx=10)
      left join ops as ops1 on (ops1.op=ops_p1.p)
      left join ops as ops2 on (ops2.op=ops_p2.p)
      left join ops as ops3 on (ops3.op=ops_p3.p)
      left join ops as ops4 on (ops4.op=ops_p4.p)
      left join ops as ops5 on (ops5.op=ops_p5.p)
      left join ops as ops6 on (ops6.op=ops_p6.p)
      left join ops as ops7 on (ops7.op=ops_p7.p)
      left join ops as ops8 on (ops8.op=ops_p8.p)
      left join ops as ops9 on (ops9.op=ops_p9.p)
      left join ops as opsa on (opsa.op=ops_pa.p)
''',
    ]:
      self.db.execute(s)

  def __enter__(self):
    self.db.__enter__()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.db.__exit__(exc_type, exc_value, traceback)

  def op_finalize(self):
    self.db.execute('vacuum analyze')

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
    self.db.executemany('insert into ops_method(op,method) values (?,?)', ((str(o._id), str(method._id)) for o in ops))

  def op_mark_class(self, ops, class_, ignore_dupes=False):
    if not ignore_dupes:
      self.db.executemany('insert into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in ops))
    else:
      self.db.executemany('insert or ignore into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in ops))
