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

import re
import sys
from collections import deque

from trueseeing.core.code.model import Annotation
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Iterable, ContextManager, Optional, Type, TextIO, List, Tuple, TypeVar
  from types import TracebackType
  from trueseeing.core.code.model import Token, Op
  from trueseeing.core.store import Store

  T = TypeVar('T')

class SmaliAnalyzer:
  store: Store
  def __init__(self, store: Store) -> None:
    self.store = store

  def __enter__(self) -> SmaliAnalyzer:
    return self

  def __exit__(self, exc_type: Optional[Type[BaseException]], exc_value: Optional[BaseException], traceback: Optional[TracebackType]) -> None:
    pass

  def analyze(self, fs: Iterable[TextIO]) -> None:
    import time
    analyzed_ops = 0
    analyzed_methods = 0
    analyzed_classes = 0
    started = time.time()

    for f in fs:
      reg1 = None
      reg2 = None

      for t in P.parsed_flat(f.read()):
        self.store.op_append(t)
        analyzed_ops = analyzed_ops + 1
        if analyzed_ops & 0xffff == 0:
          ui.stderr(f"\ranalyzed: {analyzed_ops} ops, {analyzed_methods} methods, {analyzed_classes} classes ({analyzed_ops / (time.time() - started):.02f} ops/s)", nl=False)

        if reg1 is not None:
          reg1.append(t)
        if reg2 is not None:
          reg2.append(t)

        if t.eq('directive', 'class'):
          if reg1 is not None:
            reg1.pop()
            self.store.op_mark_class(reg1, reg1[0])
            reg1 = [t]
            analyzed_classes = analyzed_classes + 1
          else:
            reg1 = [t]
        elif t.eq('directive', 'method'):
          if reg2 is None:
            reg2 = [t]
        elif t.eq('directive', 'end') and t.p[0].v == 'method':
          if reg2 is not None:
            self.store.op_mark_method(reg2, reg2[0])
            reg2 = None
            analyzed_methods = analyzed_methods + 1
      else:
        if reg1 is not None:
          self.store.op_mark_class(reg1, reg1[0], ignore_dupes=True)
          reg1 = None
          analyzed_classes = analyzed_classes + 1

    ui.stderr(f"\ranalyzed: {analyzed_ops} ops, {analyzed_methods} methods, {analyzed_classes} classes{' '*20}")
    ui.stderr("analyzed: finalizing")
    self.store.op_finalize()
    ui.stderr(f"analyzed: done ({time.time() - started:.02f} sec)")

class P:
  @staticmethod
  def head_and_tail(xs: List[T]) -> Tuple[T, Optional[List[T]]]:
    try:
      return xs[0], xs[1:]
    except IndexError:
      return xs[0], None

  @staticmethod
  def parsed_flat(s: str) -> Iterable[Op]:
    q = deque(re.split(r'\n+', s))
    while q:
      l = q.popleft()
      if l:
        t = P.parsed_as_op(l)
        if t.eq('directive', 'annotation'):
          yield Annotation(t.v, t.p, P.parsed_as_annotation_content(q))
        else:
          yield t

  @staticmethod
  def parsed_as_op(l: str) -> Op:
    x, xs = P.head_and_tail(list(P.lexed_as_smali(l)))
    return Op(x.t, x.v, [Op(y.t, y.v) for y in xs] if xs else None)

  @staticmethod
  def parsed_as_annotation_content(q: deque[str]) -> List[str]:
    content = []
    try:
      while '.end annotation' not in q[0]:
        content.append(q.popleft())
    except IndexError:
      pass
    return content

  @staticmethod
  def lexed_as_smali(l: str) -> Iterable[Token]:
    for m in re.finditer(r':(?P<label>[a-z0-9_-]+)|{\s*(?P<multilabel>(?::[a-z0-9_-]+(?: .. )*)+\s*)}|\.(?P<directive>[a-z0-9_-]+)|"(?P<string>.*)"|(?P<reg>[vp][0-9]+)|{(?P<multireg>[vp0-9,. ]+)}|(?P<id>[a-z][a-z/-]*[a-z0-9/-]*)|(?P<reflike>[A-Za-z_0-9/;$()<>\[-]+(?::[A-Za-z_0-9/;$()<>\[-]+)?)|#(?P<comment>.*)', l):
      key = m.lastgroup
      if key:
        value = m.group(key)
        yield Token(key, value)
