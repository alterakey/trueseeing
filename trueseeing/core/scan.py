from __future__ import annotations
from typing import TYPE_CHECKING

from contextlib import contextmanager

if TYPE_CHECKING:
  from typing import List, Optional, Iterator, Dict, Any
  from trueseeing.api import DetectorEntry, DetectorHelper, DetectorMap
  from trueseeing.core.context import Context, ContextType
  from trueseeing.core.android.db import Query
  from trueseeing.core.model.issue import Issue

class Scanner:
  _helper: DetectorHelper
  _sigs: Dict[str, DetectorEntry]

  def __init__(self, context: Context, sigsels: List[str] = [], excludes: List[str] = [], max_graph_size: Optional[int] = None) -> None:
    self._helper = DetectorHelperImpl(self)
    self._context = context
    self._sigs = dict()
    self._excludes = excludes
    self._max_graph_size = max_graph_size

    self._init_sigs(['all'] + sigsels)

  def get_active_signatures(self) -> DetectorMap:
    return self._sigs

  @classmethod
  def get_all_signatures(cls) -> DetectorMap:
    return Scanner(context=None).get_active_signatures()  # type: ignore[arg-type]

  async def scan(self, q: Query) -> int:
    import asyncio
    from pubsub import pub
    from trueseeing.core.android.analysis.flow import DataFlows
    with DataFlows.apply_max_graph_size(self._max_graph_size):
      with self._apply_excludes_on_context():
        def _detected(issue: Issue) -> None:
          q.issue_raise(issue)

        pub.subscribe(_detected, 'issue')
        await asyncio.gather(*[e['e']() for e in self._sigs.values()])
        pub.unsubscribe(_detected, 'issue')

        return q.issue_count()

  async def clear(self, q: Query) -> None:
    q.issue_clear()

  @contextmanager
  def _apply_excludes_on_context(self) -> Iterator[None]:
    o = self._context.excludes
    self._context.excludes = self._excludes
    yield None
    self._context.excludes = o

  @classmethod
  def _sigsel_matches(cls, sigid: str, sels: List[str]) -> bool:
    def _match(sigid: str, sel: str) -> bool:
      neg = False
      if sel.startswith('no-'):
        sel = sel[3:]
        neg = True
      if sel == 'all':
        return not neg
      elif sel.endswith('-all'):
        psel = sel[:-4]
        return neg ^ sigid.startswith(psel)
      else:
        return neg ^ (sigid == sel)
    o: bool = False
    for x in sels:
      o = _match(sigid, x)
    return o

  def _init_sigs(self, sigsels: List[str]) -> None:
    from itertools import chain
    from trueseeing.sig import discover
    from trueseeing.core.ext import Extension
    for clazz in chain(discover(), Extension.get().get_signatures()):
      t = clazz.create(self._helper)
      for k,v in t.get_descriptor().items():
        if self._sigsel_matches(k, sigsels):
          self._sigs[k] = v

class DetectorHelperImpl:
  def __init__(self, scanner: Scanner) -> None:
    self._s = scanner
  def get_context(self, typ: Optional[ContextType] = None) -> Any:
    if typ:
      self._s._context.require_type(typ)
    return self._s._context
  def raise_issue(self, issue: Issue) -> None:
    from pubsub import pub
    pub.sendMessage('issue', issue=issue)
