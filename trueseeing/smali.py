import re
import collections
import itertools

import pprint
import traceback

class Token:
  t = None
  v = None

  def __init__(self, t, v):
    self.t = t
    self.v = v

  def __repr__(self):
    return '<Token %s:%s>' % (self.t, self.v)

class Program(collections.UserList):
  pass

class Op(Token):
  p = None

  def __init__(self, t, v, p):
    super().__init__(t, v)
    self.p = p

  def __repr__(self):
    return '<Op %s:%s:%s>' % (self.t, self.v, self.p)

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
      
class DataFlows:
  class NoSuchValueError(Exception):
    pass
  
  class RegisterDecodeError(Exception):
    pass

  @staticmethod
  def likely_calling_in(ops):
    pass
  
  @staticmethod
  def into(o):
    return DataFlows.analyze(o)

  @staticmethod
  def decoded_registers_of(ref, type_=frozenset):
    if ref.t == 'multireg':
      regs = ref.v
      if ' .. ' in regs:
        from_, to_ = reg.split(' .. ')
        return type_(['%s%d' % (from_[0], c) for c in range(int(from_[1]), int(to_[1]) + 1)])
      elif ',' in regs:
        return type_([r.strip() for r in regs.split(',')])
      else:
        return type_([regs.strip()])
    elif ref.t == 'reg':
      regs = ref.v
      return type_([regs.strip()])
    else:
      raise DataFlows.RegisterDecodeError("unknown type of reference: %s, %s" % (ref.t, ref.v))

  @staticmethod
  def looking_behind_from(op, ops):
    focus = None
    for o in reversed(ops[:ops.index(op)]):
      if focus is None:
        if o.t != 'label':
          yield o
        else:
          if not o.v.startswith("try_"):
            focus = o.v
      else:
        if o.t != 'id' or not any(p.v == focus for p in o.p):
          continue
        else:
          focus = None          

  @staticmethod
  def solved_constant_data_in_invocation(invokation_op, index):
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = DataFlows.analyze(invokation_op)
    reg = DataFlows.decoded_registers_of(invokation_op.p[0], type_=list)[index + (0 if invokation_op.v.endswith('-static') else 1)]
    arg = graph[invokation_op][reg]
    if arg.t == 'id' and arg.v.startswith('const'):
      return arg.p[1].v
    else:
      raise DataFlows.NoSuchValueError('not a compile-time constant: %r' % arg)

  @staticmethod
  def walk_dict_values(d):
    try:
      for v in d.values():
        yield from DataFlows.walk_dict_values(v)
    except AttributeError:
      yield d
      
  @staticmethod
  def solved_possible_constant_data_in_invocation(invokation_op, index):
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = DataFlows.analyze(invokation_op)
    reg = DataFlows.decoded_registers_of(invokation_op.p[0], type_=list)[index + (0 if invokation_op.v.endswith('-static') else 1)]
    return {x.p[1].v for x in DataFlows.walk_dict_values(graph[invokation_op][reg]) if x is not None and x.t == 'id' and x.v.startswith('const')}
    
  @staticmethod
  def solved_typeset_in_invocation(invokation_op, index):
    assert invokation_op.t == 'id' and invokation_op.v.startswith('invoke')
    graph = DataFlows.analyze(invokation_op)
    reg = DataFlows.decoded_registers_of(invokation_op.p[0], type_=list)[index + (0 if invokation_op.v.endswith('-static') else 1)]
    arg = graph[invokation_op][reg]
    pprint.pprint(graph)
    raise Exception('breakpoint')

  @staticmethod
  def analyze(op):
    if op is not None and op.t == 'id':
      if any(op.v.startswith(x) for x in ['const','new-','move-exception']):
        return op
      elif op.v in ['move', 'array-length']:
        return {op:{k:DataFlows.analyze(DataFlows.analyze_recent_load_of(op, k)) for k in DataFlows.decoded_registers_of(op.p[1])}}
      elif any(op.v.startswith(x) for x in ['aget-']):
        assert len(op.p) == 3
        return {op:{k:DataFlows.analyze(DataFlows.analyze_recent_array_load_of(op, k)) for k in (DataFlows.decoded_registers_of(op.p[1]) | DataFlows.decoded_registers_of(op.p[2]))}}
      elif any(op.v.startswith(x) for x in ['sget-']):
        assert len(op.p) == 2
        return {op:{k:DataFlows.analyze(DataFlows.analyze_recent_static_load_of(op)) for k in DataFlows.decoded_registers_of(op.p[0])}}
      elif any(op.v.startswith(x) for x in ['iget-']):
        assert len(op.p) == 3
        return {op:{k:DataFlows.analyze(DataFlows.analyze_recent_instance_load_of(op)) for k in DataFlows.decoded_registers_of(op.p[0])}}
      elif op.v.startswith('move-result'):
        return DataFlows.analyze(DataFlows.analyze_recent_invocation(op))
      else:
        try:
          return {op:{k:DataFlows.analyze(DataFlows.analyze_recent_load_of(op, k)) for k in DataFlows.decoded_registers_of(op.p[0])}}
        except DataFlows.RegisterDecodeError:
          return None

  @staticmethod
  def analyze_recent_static_load_of(op):
    assert op.t == 'id' and any(op.v.startswith(x) for x in ['sget-'])
    target = op.p[1].v
    for o in itertools.chain(DataFlows.looking_behind_from(op, op.method_.ops), itertools.chain(*(c.ops for c in op.method_.class_.global_.classes))):
      if o.t == 'id' and o.v.startswith('sput-'):
        if o.p[1].v == target:
          return o
    raise Exception('failed static trace of: %r' % op)

  @staticmethod
  def analyze_load(op):
    if op.t == 'id':
      if any(op.v.startswith(x) for x in ['const','new-','move','array-length','aget-','sget-','iget-']):
        return DataFlows.decoded_registers_of(op.p[0])
      elif any(op.v.startswith(x) for x in ['invoke-direct', 'invoke-virtual', 'invoke-interface']):
        # Imply modification of "this"
        return frozenset(DataFlows.decoded_registers_of(op.p[0], type_=list)[:1])
      else:
        return frozenset()

  @staticmethod
  def analyze_recent_load_of(from_, reg):
    if reg.startswith('p'):
      index = int(reg.replace('p', ''))
      for caller in CodeFlows.callers_of(from_.method_):
        caller_reg = DataFlows.decoded_registers_of(caller.p[0], type_=list)[index]
        print("analyze_recent_load_of: TBD: retrace: %s -> %s -> %r (in %r)" % (reg, caller_reg, caller, caller.method_))
      return None
    for o in DataFlows.looking_behind_from(from_, from_.method_.ops):
      if o.t == 'id':
        if reg in DataFlows.analyze_load(o):
          return o

  @staticmethod
  def analyze_recent_array_load_of(from_, reg):
    return DataFlows.analyze_recent_load_of(from_, reg)

  @staticmethod
  def analyze_recent_instance_load_of(op):
    assert len(op.p) == 3
    print("analyze_recent_instance_load_of: TBD: instansic trace of %s (%s)" % (op.p[1], op.p[2]))
    return None

  @staticmethod
  def analyze_recent_invocation(from_):
    for o in DataFlows.looking_behind_from(from_, from_.method_.ops):
      if o.t == 'id' and o.v.startswith('invoke'):
        return o

class Class(Op):
  def __init__(self, p, methods, fields):
    super().__init__('class', [t for t in p if t.t == 'reflike'][0], None)
    self.attrs = set([t for t in p if t.t == 'id'])
    self.methods = methods if methods else []
    self.fields = fields if fields else []
    self.super_ = None
    self.source = None
    self.global_ = None
    self.ops = Program()

  def __repr__(self):
    return '<Class %s:%s, attrs:%s, super:%s, source:%s, methods:[%d methods], fields:[%d fields], ops:[%d ops]>' % (self.t, self.v, self.attrs, self.super_, self.source, len(self.methods), len(self.fields), len(self.ops))

  def qualified_name(self):
    return self.v.v

class App:
  classes = []

class Annotation(Op):
  name = None
  content = None

  def __init__(self, v, p, content):
    super().__init__('annotation', v, p)
    self.content = content

  def __repr__(self):
    return '<Annotation %s:%s:%s, content:%s>' % (self.t, self.v, self.p, self.content)

class Method(Op):
  attrs = None
  ops = Program()

  def __init__(self, p, ops):
    super().__init__('method', Token('prototype', ''.join((t.v for t in p[-2:]))), p)
    self.attrs = set(p[:-2])
    self.ops = ops

  def __repr__(self):
    return '<Method %s:%s, attrs:%s, ops:[%d ops]>' % (self.t, self.v, self.attrs, len(self.ops))

  def matches(self, reflike):
    return self.qualified_name() in reflike.v

  def qualified_name(self):
    return '%s->%s' % (self.class_.qualified_name(), self.v.v)

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

    for t in P.parsed_flat(s):
      if t.t == 'directive' and t.v == 'class':
        class_ = Class(t.p, [], [])
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
              method_ = Method(t.p, [])
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
    content = []
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
