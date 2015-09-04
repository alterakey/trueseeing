import os
import unittest
from hypothesis import given
from hypothesis.strategies import text

from trueseeing import smali


import re
import collections

class Token:
  t = None
  v = None
  p = None

  def __init__(self, t, v, p):
    self.t = t
    self.v = v
    self.p = p

  def __repr__(self):
    return '<Token %s:%s:%s>' % (self.t, self.v, self.p)

class P:
  @staticmethod
  def head_and_tail(xs):
    try:
      return xs[0], xs[1:]
    except IndexError:
      return xs[0], None

  @staticmethod
  def parsed(s):
    q = collections.deque(re.split(r'\n+', s))
    while q:
      l = q.popleft()
      if l:
        x, xs = P.head_and_tail([t for t in P.lexed_as_smali(l)])
        if xs is not None:
          x.p = [t for t in xs]
        if x.t != 'directive':
          yield x
        else:
          if x.v != 'annotation':
            yield x
          else:
            if x.p is None:
              x.p = []
            x.p.append(P.lexed_as_annotation_content(q))
            yield x

  @staticmethod
  def lexed_as_smali(s):
    for m in re.finditer(r':(?P<label>[a-z0-9_-]+)|{\s*(?P<multilabel>(?::[a-z0-9_-]+(?: .. )*)+\s*)}|\.(?P<directive>[a-z0-9_-]+)|"(?P<string>.*)"|(?P<reg>[vp][0-9]+)|{(?P<multireg>[vp0-9,. ]+)}|(?P<id>[a-z0-9/-]+)|(?P<reflike>[A-Za-z_0-9/;$()<>-]+)|#(?P<comment>.*)', s):
      key = m.lastgroup
      value = m.group(key)
      yield Token(key, value, [])

  @staticmethod
  def lexed_as_class(q):
    pass

  @staticmethod
  def lexed_as_method(q):
    pass

  @staticmethod
  def lexed_as_annotation_content(q):
    contents = []
    try:
      while '.end annotation' not in q[0]:
        contents.append(q.popleft())
    except IndexError:
      pass
    return Token('content', ''.join(contents), [])

class SmaliDBTest(unittest.TestCase):
  def normal(self, c):
    pass

  def test_000(self):
    with open(os.path.join(os.path.dirname(__file__), "fixture_0.smali"), "r") as f:
      for t in P.parsed(f.read()):
        print(t)


      for o in (r for r in f if r.strip()):
        try:
          print(o)
          print(smali.Insn(o))

        except IndexError:
          pass
      assert False
