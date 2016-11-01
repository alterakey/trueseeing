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
  def callers_of(store, method):
    yield from store.query().callers_of(method)

  @staticmethod
  def callstacks_of(store, method):
    o = dict()
    for m in CodeFlows.callers_of(store, method):
      o[m] = CodeFlows.callstacks_of(store, m)
    return o

  @staticmethod
  def method_of(op, ops):
    for o in reversed(ops):
      pass

  @staticmethod
  def invocations_in(ops):
    return (o for o in ops if o.t == 'id' and 'invoke' in o.v)
