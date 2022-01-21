# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <altakey@gmail.com>
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
from collections import deque

from trueseeing.core.code.model import Op, Annotation
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Iterable, Optional, Type, TextIO, List, Tuple, TypeVar, Set
  from types import TracebackType
  from trueseeing.core.store import Store

  T = TypeVar('T')

class SmaliAnalyzer:
  _store: Store
  def __init__(self, store: Store) -> None:
    self._store = store

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

    classmap: Set[Tuple[int, int]] = set()

    begin_at = started
    with self._store.db as c:
      base_id = 1
      last_seen = analyzed_ops

      for f in fs:
        ops = []
        for op in P.parsed_flat(f.read()):
          analyzed_ops += 1
          for idx, o in enumerate(tuple([op] + op.p)):
            o._idx = idx
            ops.append(o)
        for t in ops:
          t._id = base_id
          base_id += 1
        self._store.op_store_ops(ops, c=c)

        start = None
        for t in ops:
          if t.eq('directive', 'class'):
            start = t._id
            break
        if start:
          classmap.add(tuple([start, ops[-1]._id])) # type: ignore[arg-type]

        if analyzed_ops - last_seen > 65536:
          elapsed = time.time() - begin_at
          ui.info(f"\ranalyze: {analyzed_ops} ops... ({analyzed_ops / elapsed:.02f} ops/s){' '*20}", nl=False)
          last_seen = analyzed_ops

      analyzed_ops = self._store.op_count_ops(c=c)

    ui.info(f"\ranalyze: {analyzed_ops} ops, classes... {' '*20}", nl=False)
    with self._store.db as c:
      analyzed_classes = self._store.op_store_classmap(classmap, c=c)

    ui.info(f"\ranalyze: {analyzed_ops} ops, {analyzed_classes} classes, methods...{' '*20}", nl=False)
    with self._store.db as c:
      analyzed_methods = self._store.op_generate_methodmap(c=c)

    ui.info(f"\ranalyze: {analyzed_ops} ops, {analyzed_classes} classes, {analyzed_methods} methods.{' '*20}")
    ui.stderr("analyze: finalizing")
    self._store.op_finalize()
    ui.stderr(f"analyze: done ({time.time() - started:.02f} sec)")

class P:
  @classmethod
  def parsed_flat(cls, s: str) -> Iterable[Op]:
    q = deque(re.split(r'\n+', s))
    while q:
      l = q.popleft()
      if l:
        t = cls._parsed_as_op(l)
        if t.eq('directive', 'annotation'):
          yield Annotation(t.v, t.p, P._parsed_as_annotation_content(q))
        else:
          yield t

  @classmethod
  def _head_and_tail(cls, xs: List[T]) -> Tuple[T, Optional[List[T]]]:
    try:
      return xs[0], xs[1:]
    except IndexError:
      return xs[0], None

  @classmethod
  def _parsed_as_op(cls, l: str) -> Op:
    x, xs = cls._head_and_tail(list(P._lexed_as_smali(l)))
    if xs: x.p = xs
    return x

  @classmethod
  def _parsed_as_annotation_content(cls, q: deque[str]) -> List[str]:
    content = []
    try:
      while '.end annotation' not in q[0]:
        content.append(q.popleft())
    except IndexError:
      pass
    return content

  @classmethod
  def _lexed_as_smali(cls, l: str) -> Iterable[Op]:
    for m in re.finditer(r':(?P<label>[a-z0-9_-]+)|{\s*(?P<multilabel>(?::[a-z0-9_-]+(?: .. )*)+\s*)}|\.(?P<directive>[a-z0-9_-]+)|"(?P<string>.*)"|#(?P<comment>.*)|(?P<reg>[vp][0-9]+)|{(?P<multireg>[vp0-9,. ]+)}|(?P<id>[a-z][a-z/-]*[a-z0-9/-]*)|(?P<reflike>[^ ]+)', l):
      key = m.lastgroup
      if key:
        value = m.group(key)
        if key == 'reflike' and value == ',':
          pass
        else:
          yield Op(key, value)
