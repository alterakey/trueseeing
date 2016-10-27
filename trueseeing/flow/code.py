import itertools
import re
import logging

log = logging.getLogger(__name__)

class InvocationPattern:
  def __init__(self, insn, value, i=None):
    self.insn = insn
    self.value = value
    self.i = i

class CodeFlows:
  @staticmethod
  def callers_of(method):
    for r in (x for x in itertools.chain(*(c.ops for c in method.class_.global_.classes)) if x.t == 'id' and 'invoke' in x.v):
      try:
        ref = r.p[1].v
      except IndexError:
        ref = r.p[0].v
      if method.qualified_name() in ref:
        yield r

  @staticmethod
  def callstacks_of(method):
    o = dict()
    for m in CodeFlows.callers_of(method):
      o[m] = CodeFlows.callstacks_of(m)
    return o

  @staticmethod
  def method_of(op, ops):
    for o in reversed(ops):
      pass

  @staticmethod
  def invocations_in(ops):
    return (o for o in ops if o.t == 'id' and 'invoke' in o.v)
