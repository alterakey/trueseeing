import random
import hashlib
import os.path
import sqlite3
import itertools

class SQLite3Store:
  def __init__(self, path):
    self.db = sqlite3.connect(os.path.join(path, 'store.db'))

  def token_bucket(self, name):
    return SQLite3TokenBucket(self.db, name)

class SQLite3Attachable:
  def __init__(self, db):
    self.db = db

  def __enter__(self):
    self.db.__enter__()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.db.__exit__(exc_type, exc_value, traceback)

class SQLite3TokenBucket(SQLite3Attachable):
  def __init__(self, db, prefix):
    super().__init__(db)
    self.prefix = prefix.decode('ascii')
    for s in [
        'create table if not exists %(prefix)s (id integer primary key, t string not null, v string not null)',
        'create table if not exists %(prefix)s_p (id integer not null, idx integer not null, p integer not null)'
    ]:
      self.db.execute(s % dict(prefix=self.prefix))

  def get(self, k):
    for t,v in self.db.execute('select t,v from %(prefix)s where id=?' % dict(prefix=self.prefix), (k)):
      return Token(t, v)

  def put(self, k, token):
    self.db.execute('replace into %(prefix)s(id,t,v) values (?,?,?)' % dict(prefix=self.prefix), (k, token.t.encode('ascii'), token.v.encode('ascii')))
    self.db.execute('delete from %(prefix)s_p where id=?' % dict(prefix=self.prefix), (k))
    self.db.executemany('insert into %(prefix)s_p(id, idx, p) values (?,?,?)' % dict(prefix=self.prefix), ((k,i,token.p[i]) for i in range(len(token.p))))

  def append(self, token):
    ids = []
    for t in itertools.chain([token], token.p):
      self.db.execute('insert into %(prefix)s(t,v) values (?,?)' % dict(prefix=self.prefix), (t.t.encode('ascii'), t.v.encode('ascii')))
      for r in self.db.execute('select id from %(prefix)s where rowid=last_insert_rowid() limit 1' % dict(prefix=self.prefix)):
        ids.append(r[0])
    self.db.executemany('insert into %(prefix)s_p(id, idx, p) values (?,?,?)' % dict(prefix=self.prefix), ((ids[0], i, ids[i + 1]) for i in range(len(token.p))))

  def delete(self, k):
    self.db.execute('delete from %(prefix)s where id=?' % dict(prefix=self.prefix), (k))
    self.db.execute('delete from %(prefix)s_p where id=? or p=?' % dict(prefix=self.prefix), (k, k))

Store = SQLite3Store
TokenBucket = SQLite3TokenBucket
