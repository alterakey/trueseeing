from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from typing import Iterable, Mapping, Any
  from trueseeing.core.store import Store
  from trueseeing.core.code.model import Op

class CodeFlows:
  @classmethod
  def callers_of(cls, store: Store, method: Op) -> Iterable[Op]:
    yield from store.query().callers_of(method)

  @classmethod
  def callstacks_of(cls, store: Store, method: Op) -> Mapping[Op, Any]:
    o = dict()
    for m in cls.callers_of(store, method):
      o[m] = cls.callstacks_of(store, m)
    return o
