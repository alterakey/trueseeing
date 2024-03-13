from __future__ import annotations
from typing import TYPE_CHECKING

import re

from trueseeing.core.android.model import Op, Token

if TYPE_CHECKING:
  from typing import Iterator, TypeVar

  T = TypeVar('T')

class OpAnalyzer:
  def get_insn(self, o: Op) -> str:
    t = self.get_mnemonic(o)
    if t.t != 'id':
      raise ValueError(t)
    return t.v

  def get_mnemonic(self, o: Op) -> Token:
    return self._first(self._lex(o.l))

  def get_param(self, o: Op, i: int) -> Token:
    return self._getn(self._lex(o.l), i + 1)

  def get_param_count(self, o: Op) -> int:
    return self._count(self._lex(o.l)) - 1

  def tokenize(self, o: Op) -> Iterator[Token]:
    return self._lex(o.l)

  def _lex(cls, l: str) -> Iterator[Token]:
    for m in re.finditer(r':(?P<label>[a-z0-9_-]+)|{\s*(?P<multilabel>(?::[a-z0-9_-]+(?: .. )*)+\s*)}|\.(?P<directive>[a-z0-9_-]+)|"(?P<string>.*)"|#(?P<comment>.*)|(?P<reg>[vp][0-9]+)|{(?P<multireg>[vp0-9,. ]+)}|(?P<id>[a-z][a-z/-]*[a-z0-9/-]*)|(?P<reflike>[^ ]+)', l):
      key = m.lastgroup
      if key:
        value = m.group(key)
        if key == 'reflike' and value == ',':
          pass
        else:
          yield Token(key, value)

  def _first(self, xs: Iterator[T]) -> T:
    return self._getn(xs, 0)

  def _getn(self, xs: Iterator[T], i: int) -> T:
    for n, x in enumerate(xs):
      if n == i:
        return x
    raise IndexError()

  def _count(self, xs: Iterator[T]) -> int:
    n = 0
    for _ in xs:
      n += 1
    return n
