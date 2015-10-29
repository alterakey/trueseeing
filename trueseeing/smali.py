import re
import collections
import itertools

class Package:
  def __init__(self, apk):
    self.apk = apk

  def disassembled(self):
    return PackageAnalysis(PackageContent(self.apk).unpacked()).analyzed()

class PackageAnalysis:
  res = None
  smali = None
  unknown = None
  lib = None

  def __init__(self, path):
    self.path = path

  def analyzed(self):
    self.res = []
    self.smali = []
    self.unknown = []
    self.lib = []

class PackageContent:
  def __init__(self, apk):
    self.apk = apk

  def unpacked(self):
    return '/tmp/package/unpacked'

class Directory:
  def __init__(self, path):
    self.path = path

  def remove(self):
    os.path.rmtree(self.path)

  def __enter__(self):
    return self

  def __exit__(self, exc_code, exc_value, traceback):
    self.remove()

class Smali:
  @staticmethod
  def parsed(source_code_in_smali):
    return P.parsed(source_code_in_smali)

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
    try:
      return (r for r in itertools.chain(*(c.ops for c in method.class_.global_.classes)) if r.t == 'id' and 'invoke' in r.v and method.matches(r.p[1]))
    except:
      return []

  @staticmethod
  def callstacks_of(method):
    o = dict()
    for m in CodeFlows.callers_of(method):
      o[m] = CodeFlows.callstacks_of(m)
    return o

  @staticmethod
  def invocations_in(ops):
    return (o for o in ops if o.t == 'id' and 'invoke' in o.v)

class DataFlows:
  @staticmethod
  def _immediate_into(op):
    o = dict()
    for r in DataFlows.decoded_registers_of(op.p[0]):
      for d in [x for x in DataFlows.transits_from(op) if r in x.get('load', set())]:
        if r not in o:
          o[r] = d['on']
    return o

  @staticmethod
  def into(o):
    for k,v in DataFlows._immediate_into(o).items():
      if 'invoke' in v.v:
        for t in DataFlows.into(v):
          yield t
      else:
        yield v

  @staticmethod
  def decoded_registers_of(ref):
    if ref.t == 'multireg':
      regs = ref.v
      if ' .. ' in regs:
        from_, to_ = reg.split(' .. ')
        return set(['%s%d' % (from_[0], c) for c in range(int(from_[1]), int(to_[1]) + 1)])
      elif ',' in regs:
        return set([r.strip() for r in regs.split(',')])
      else:
        return set([regs.strip()])
    elif ref.t == 'reg':
      regs = ref.v
      return set([regs.strip()])
    else:
      raise ValueError("unknown type of reference: %s, %s", ref.t, ref.v)

  @staticmethod
  def transits_from(op):
    looked = set()
    for o in reversed(op.method_.ops[:op.method_.ops.index(op)]):
      if o not in looked:
        looked.add(o)
        if o.t == 'id':
          if o.v.startswith('move-result'):
            for r in reversed(op.method_.ops[:o.method_.ops.index(o)]):
              if r.t == 'id' and r.v.startswith('invoke'):
                looked.add(r)
                yield dict(load=DataFlows.decoded_registers_of(o.p[0]), access=DataFlows.decoded_registers_of(r.p[0]), on=r)
                break
          else:
            if o.v.startswith('const'):
              yield dict(load=DataFlows.decoded_registers_of(o.p[0]), on=o)
            elif o.v.startswith('new-'):
              yield dict(load=DataFlows.decoded_registers_of(o.p[0]), on=o)
            elif o.v == 'move-exception':
              yield dict(load=DataFlows.decoded_registers_of(o.p[0]), on=o)
            elif o.v == 'move':
              yield dict(load=DataFlows.decoded_registers_of(o.p[0]), access=DataFlows.decoded_registers_of(o.p[1]), on=o)
            else:
              try:
                yield dict(access=DataFlows.decoded_registers_of(o.p[0]), on=o)
              except ValueError:
                pass

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

    for t in (r for r in P.parsed_flat(s)):
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
    x, xs = P.head_and_tail([t for t in P.lexed_as_smali(l)])
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
    for m in re.finditer(r':(?P<label>[a-z0-9_-]+)|{\s*(?P<multilabel>(?::[a-z0-9_-]+(?: .. )*)+\s*)}|\.(?P<directive>[a-z0-9_-]+)|"(?P<string>.*)"|(?P<reg>[vp][0-9]+)|{(?P<multireg>[vp0-9,. ]+)}|(?P<id>[a-z0-9/-]+)|(?P<reflike>[A-Za-z_0-9/;$()<>-]+)|#(?P<comment>.*)', l):
      key = m.lastgroup
      value = m.group(key)
      yield Token(key, value)

if __name__ == '__main__':
    Package(apk).disassembled().of('filename.smali')
