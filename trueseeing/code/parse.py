import re
import collections
import itertools

import pprint
import traceback
from .model import *
from trueseeing.store import Store, TokenBucket

class P:
  @staticmethod
  def head_and_tail(xs):
    try:
      return xs[0], xs[1:]
    except IndexError:
      return xs[0], None

  @staticmethod
  def parsed(s):
    app = App()
    class_ = None
    method_ = None

    with Store('.').token_bucket(b'ops') as b:
      for t in P.parsed_flat(s):
        b.append(t)
        if t.t == 'directive' and t.v == 'class':
          class_ = Class(t.p)
          class_.global_ = app
          app.classes.append(class_)
        else:
          assert class_ is not None
          t.class_ = class_
          class_.ops.append(t)
          if method_ is None:
            if t.t == 'directive':
              if t.v == 'super':
                class_.super_ = t.p[0]
              elif t.v == 'source':
                class_.source = t.p[0]
              elif t.v == 'method':
                method_ = Method(t.p)
                method_.class_ = class_
              else:
                pass
          else:
            t.method_ = method_
            if isinstance(t, Annotation):
              method_.p.append(t)
            else:
              if t.t == 'directive' and t.v == 'end' and t.p[0].v == 'method':
                class_.methods.append(method_)
                method_ = None
              else:
                method_.ops.append(t)

      return class_

  @staticmethod
  def parsed_flat(s):
    q = collections.deque(re.split(r'\n+', s))
    while q:
      l = q.popleft()
      if l:
        t = P.parsed_as_op(l)
        if t.t == 'directive' and t.v == 'annotation':
          yield Annotation(t.v, t.p, P.parsed_as_annotation_content(q))
        else:
          yield t

  @staticmethod
  def parsed_as_op(l):
    x, xs = P.head_and_tail(list(P.lexed_as_smali(l)))
    return Op(x.t, x.v, xs)

  @staticmethod
  def parsed_as_annotation_content(q):
    content = Program()
    try:
      while '.end annotation' not in q[0]:
        content.append(q.popleft())
    except IndexError:
      pass
    return content

  @staticmethod
  def lexed_as_smali(l):
    for m in re.finditer(r':(?P<label>[a-z0-9_-]+)|{\s*(?P<multilabel>(?::[a-z0-9_-]+(?: .. )*)+\s*)}|\.(?P<directive>[a-z0-9_-]+)|"(?P<string>.*)"|(?P<reg>[vp][0-9]+)|{(?P<multireg>[vp0-9,. ]+)}|(?P<id>[a-z][a-z/-]*[a-z0-9/-]*)|(?P<reflike>[A-Za-z_0-9/;$()<>\[-]+(?::[A-Za-z_0-9/;$()<>\[-]+)?)|#(?P<comment>.*)', l):
      key = m.lastgroup
      value = m.group(key)
      yield Token(key, value)
