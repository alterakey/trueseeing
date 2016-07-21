import random
import hashlib
import os.path
import sqlite3

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
    for s in ['create table if not exists %(prefix)s (id integer primary key, t string, v string)']:
      self.db.execute(s % dict(prefix=self.prefix))

  def get(self, k):
    for t,v in self.db.execute('select t,v from %(prefix)s where id=?' % dict(prefix=self.prefix), (k)):
      return Token(t, v)

  def put(self, k, token):
    self.db.execute('replace into %(prefix)s(id,t,v) values (?,?,?)' % dict(prefix=self.prefix), (k, token.t.encode('ascii'), token.v.encode('ascii')))

  def append(self, token):
    self.db.execute('insert into %(prefix)s(t,v) values (?,?)' % dict(prefix=self.prefix), (token.t.encode('ascii'), token.v.encode('ascii')))

  def delete(self, k):
    self.db.execute('delete from %(prefix)s where id=?' % dict(prefix=self.prefix), (k))

Store = SQLite3Store
TokenBucket = SQLite3TokenBucket
