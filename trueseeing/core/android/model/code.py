from __future__ import annotations
from typing import TYPE_CHECKING

import attr

if TYPE_CHECKING:
  from typing import Optional, List

class Op:
  t: str
  v: str
  p: List[Op]
  _id: Optional[int] = None
  _idx: Optional[int] = None
  def __init__(self, t: str, v: str, p: Optional[List[Op]] = None, id_: Optional[int]=None):
    self.t = t
    self.v = v
    if p is not None:
      self.p = p
    else:
      self.p = []
    if id_ is not None:
      self._id = id_

  def __repr__(self) -> str:
    return f'<Op[{self._id}] t={self.t} v={self.v}, p={self.p}>'

  def eq(self, t: str, v: str) -> bool:
    return (self.t, self.v) == (t, v)

class Annotation(Op):
  content: List[str]
  def __init__(self, v: str, p: List[Op], content: List[str]) -> None:
    super().__init__('annotation', v, p)
    self.name = None
    self.content = content

  def __repr__(self) -> str:
    return f'<Annotation {self.t}:{self.v}:{self.p}, content:{self.content}>'

class Param(Op):
  content: List[str]
  def __init__(self, v: str, p: List[Op], content: List[str]) -> None:
    super().__init__('param', v, p)
    self.name = None
    self.content = content

  def __repr__(self) -> str:
    return f'<Param {self.t}:{self.v}:{self.p}, content:{self.content}>'

@attr.s(auto_attribs=True, frozen=True)
class InvocationPattern:
  insn: str
  value: str
  i: Optional[int] = None
