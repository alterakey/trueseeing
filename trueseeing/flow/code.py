import itertools
import re

class InvocationPattern:
  def __init__(self, insn, value, i=None):
    self.insn = insn
    self.value = value
    self.i = i

class OpMatcher:
  def __init__(self, ops, *pats):
    self.ops = ops
    self.pats = pats

  def matching(self):
    table = [(re.compile(p.insn), (re.compile(p.value) if p.value is not None else None)) for p in self.pats]
    for o in (o for o in self.ops if o.t == 'id'):
      try:
        if any(ipat.match(o.v) and (vpat is None or vpat.match(o.p[1].v)) for ipat, vpat in table):
          yield o
      except (IndexError, AttributeError):
        pass

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

