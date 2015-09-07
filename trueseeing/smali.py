import re
import collections

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

class Op(Token):
  p = None

  def __init__(self, t, v, p):
    super().__init__(t, v)
    self.p = p

  def __repr__(self):
    return '<Op %s:%s:%s>' % (self.t, self.v, self.p)

class Class(Op):
  attrs = None
  methods = []
  fields = []
  super_ = None
  source = None
  ops = []

  def __init__(self, p, methods, fields):
    super().__init__('class', [t for t in p if t.t == 'reflike'][0], None)
    self.attrs = set([t for t in p if t.t == 'id'])
    if methods:
      self.methods = methods
    if fields:
      self.fields = fields

  def __repr__(self):
    return '<Class %s:%s, attrs:%s, super:%s, source:%s, methods:[%d methods], fields:[%d fields], ops:[%d ops]>' % (self.t, self.v, self.attrs, self.super_, self.source, len(self.methods), len(self.fields), len(self.ops))

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
  ops = None

  def __init__(self, p, ops):
    super().__init__('method', Token('prototype', ''.join((t.v for t in p[-2:]))), p)
    self.attrs = set(p[:-2])
    self.ops = ops

  def __repr__(self):
    return '<Method %s:%s, attrs:%s, ops:[%d ops]>' % (self.t, self.v, self.attrs, len(self.ops))

class P:
  @staticmethod
  def head_and_tail(xs):
    try:
      return xs[0], xs[1:]
    except IndexError:
      return xs[0], None

  @staticmethod
  def parsed(s):
    class_ = None
    method_ = None

    for t in (r for r in P.parsed_flat(s)):
      if class_ is None:
        if t.t == 'directive' and t.v == 'class':
          class_ = Class(t.p, [], [])
      else:
        class_.ops.append(t)
        if method_ is None:
          if t.t == 'directive':
            if t.v == 'super':
              class_.super_ = t.p[0]
            elif t.v == 'source':
              class_.source = t.p[0]
            elif t.v == 'method':
              method_ = Method(t.p, [])
            else:
              pass
        else:
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
