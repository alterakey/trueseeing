import re
import collections
import itertools

import pprint
import traceback
from .model import *
from trueseeing.store import Store

import logging
import time
import sys

log = logging.getLogger(__name__)

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

    analyzed_ops = 0
    analyzed_methods = 0
    analyzed_classes = 0
    started = time.time()

    reg1 = None
    reg2 = None

    with Store('.') as b:
      for t in P.parsed_flat(s):
        b.op_append(t)
        analyzed_ops = analyzed_ops + 1
        if analyzed_ops & 0xffff == 0:
          sys.stderr.write("\ranalyzed: %d ops, %d methods, %d classes (%.02f ops/s)" % (analyzed_ops, analyzed_methods, analyzed_classes, analyzed_ops / (time.time() - started)))

        if reg1 is not None:
          reg1.append(t)
        if reg2 is not None:
          reg2.append(t)

        if t.t == 'directive' and t.v == 'class':
          if reg1 is not None:
            reg1.pop()
            b.op_mark_class(reg1, reg1[0])
            reg1 = [t]
            analyzed_classes = analyzed_classes + 1
          else:
            reg1 = [t]
        elif t.t == 'directive' and t.v == 'method':
          if reg2 is None:
            reg2 = [t]
        elif t.t == 'directive' and t.v == 'end' and t.p[0].v == 'method':
          if reg2 is not None:
            b.op_mark_method(reg2, reg2[0])
            reg2 = None
            analyzed_methods = analyzed_methods + 1
      else:
        if reg1 is not None:
          b.op_mark_class(reg1, reg1[0], ignore_dupes=True)
          reg1 = None
          analyzed_classes = analyzed_classes + 1

      sys.stderr.write(("\ranalyzed: %d ops, %d methods, %d classes" + (" " * 20) + "\n") % (analyzed_ops, analyzed_methods, analyzed_classes))
      sys.stderr.write("analyzed: finalizing\n")
      b.op_finalize()
      sys.stderr.write("analyzed: done (%.02f sec)\n" % (time.time() - started))
      return None

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
