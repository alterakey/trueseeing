import random
import hashlib
import os.path
import sqlite3
import itertools

class Store:
  def __init__(self, path):
    self.db = sqlite3.connect(os.path.join(path, 'store.db'))
    for s in [
        'create table if not exists ops (op integer primary key, t varchar not null, v varchar not null)',
        'create table if not exists ops_p (op integer not null, idx integer not null, p integer not null)',
        'create table if not exists ops_method (op integer not null, method integer not null)',
        'create table if not exists ops_class (op integer not null, class integer not null)',
        'create index ops_method_method on ops_method (method)',
        'create index ops_class_class on ops_class (class)',
        'create index ops_p_op on ops_p (op)',
    ]:
      self.db.execute(s)

  def __enter__(self):
    self.db.__enter__()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.db.__exit__(exc_type, exc_value, traceback)

  def op_get(self, k):
    for t,v in self.db.execute('select t,v from ops where id=?', (k)):
      return Token(t, v)

  def op_append(self, op):
    ids = []
    for t in itertools.chain([op], op.p):
      self.db.execute('insert into ops(t,v) values (?,?)', (t.t, t.v))
      for r in self.db.execute('select op from ops where rowid=last_insert_rowid() limit 1'):
        ids.append(r[0])
    self.db.executemany('insert into ops_p(op, idx, p) values (?,?,?)', ((ids[0], i, ids[i + 1]) for i in range(len(op.p))))
    for t, id_ in zip(itertools.chain([op], op.p), ids):
      t._id = id_

  def op_mark_method(self, ops, method):
    self.db.executemany('insert into ops_method(op,method) values (?,?)', ((str(o._id), str(method._id)) for o in ops))

  def op_mark_class(self, ops, class_):
    self.db.executemany('insert into ops_class(op,class) values (?,?)', ((str(o._id), str(class_._id)) for o in ops))
