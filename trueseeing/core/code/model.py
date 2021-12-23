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

from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.core.code.op import Token, Op

if TYPE_CHECKING:
  from typing import Optional, List

class Class(Op):
  methods: List[Method]
  super_: Optional[Class]
  ops: List[Op]
  def __init__(self, p: List[Token]) -> None:
    super().__init__('class', [t for t in p if t.t == 'reflike'][0], None)
    self.attrs = set([t for t in p if t.t == 'id'])
    self.methods = []
    self.fields = []
    self.super_ = None
    self.source = None
    self.global_ = None
    self.ops = []

  def __repr__(self) -> str:
    return '<Class %s:%s, attrs:%s, super:%s, source:%s, methods:[%d methods], fields:[%d fields], ops:[%d ops]>' % (self.t, self.v, self.attrs, self.super_, self.source, len(self.methods), len(self.fields), len(self.ops))

  def qualified_name(self) -> str:
    return self.v.v

class App:
  classes: List[Class]
  def __init__(self) -> None:
    self.classes = []

class Annotation(Op):
  content: List[str]
  def __init__(self, v: Token, p: List[Token], content: List[str]) -> None:
    super().__init__('annotation', v, p)
    self.name = None
    self.content = content

  def __repr__(self) -> str:
    return '<Annotation %s:%s:%s, content:%s>' % (self.t, self.v, self.p, self.content)

class Method(Op):
  ops: List[Op]
  def __init__(self, p: List[Token]) -> None:
    super().__init__('method', Token('prototype', ''.join((t.v for t in p[-2:]))), p)
    self.attrs = set(p[:-2])
    self.ops = []

  def __repr__(self) -> str:
    return '<Method %s:%s, attrs:%s, ops:[%d ops]>' % (self.t, self.v, self.attrs, len(self.ops))

  def matches(self, reflike: Token) -> bool:
    return self.qualified_name() in reflike.v

  def qualified_name(self) -> str:
    return '%s->%s' % (self.class_.qualified_name(), self.v.v)
