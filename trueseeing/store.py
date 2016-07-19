import random
import hashlib

class Store:
  def __init__(self, f):
    self.f = dict()

  def bucket(self, name):
    return Bucket(self.f, name)

class Bucket:
  def __init__(self, f, name):
    self.f = f
    self.name = bytes(name)
    if self.name not in self.f:
      self.f[self.name] = dict()
    self.b = self.f[name]

  def get(self, k):
    return self.f[k]

  def put(self, k, v):
    if k is None:
      k = self.key()
    self.f[k] = bytes(v)
    return k

  def delete(self, k):
    del self.f[k]

  @staticmethod
  def key(self):
    return bytes(hashlib.sha1(random.getrandbits(256)).hexdigest())
