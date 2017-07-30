# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

class ClassList(collections.UserList):
  pass

class MethodList(collections.UserList):
  pass

class FieldList(collections.UserList):
  pass

class Op(Token):
  p = None

  def __init__(self, t, v, p, id_=None):
    super().__init__(t, v)
    self.p = p
    self._id = id_

  def __repr__(self):
    return '<Op(%d) %s:%s:%s>' % (self._id, self.t, self.v, self.p)

  @staticmethod
  def of_id(id_):
    return Op(None, None, None, id_)

class Class(Op):
  def __init__(self, p):
    super().__init__('class', [t for t in p if t.t == 'reflike'][0], None)
    self.attrs = set([t for t in p if t.t == 'id'])
    self.methods = MethodList()
    self.fields = FieldList()
    self.super_ = None
    self.source = None
    self.global_ = None
    self.ops = Program()

  def __repr__(self):
    return '<Class %s:%s, attrs:%s, super:%s, source:%s, methods:[%d methods], fields:[%d fields], ops:[%d ops]>' % (self.t, self.v, self.attrs, self.super_, self.source, len(self.methods), len(self.fields), len(self.ops))

  def qualified_name(self):
    return self.v.v

class App:
  classes = None

  def __init__(self):
    self.classes = ClassList()

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

  def __init__(self, p):
    super().__init__('method', Token('prototype', ''.join((t.v for t in p[-2:]))), p)
    self.attrs = set(p[:-2])
    self.ops = Program()

  def __repr__(self):
    return '<Method %s:%s, attrs:%s, ops:[%d ops]>' % (self.t, self.v, self.attrs, len(self.ops))

  def matches(self, reflike):
    return self.qualified_name() in reflike.v

  def qualified_name(self):
    return '%s->%s' % (self.class_.qualified_name(), self.v.v)
