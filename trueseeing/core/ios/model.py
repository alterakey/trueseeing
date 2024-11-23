from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from typing import TypedDict

  class Call(TypedDict):
    path: str
    sect: str
    offs: int
    priv: bool
    swift: bool
    objc: bool
    cpp: bool
    target: str
