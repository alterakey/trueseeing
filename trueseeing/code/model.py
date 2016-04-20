import collections

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
