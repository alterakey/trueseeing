from __future__ import annotations
from typing import TYPE_CHECKING

from contextlib import contextmanager

if TYPE_CHECKING:
  from typing import List, Type, Optional, Iterator
  from trueseeing.core.android.context import Context
  from trueseeing.core.android.db import Query
  from trueseeing.core.report import ReportGenerator
  from trueseeing.core.model.sig import Detector
  from trueseeing.core.model.issue import Issue

class Scanner:
  def __init__(self, context: Context, reporter: ReportGenerator, sigs: List[Type[Detector]], excludes: List[str] = [], max_graph_size: Optional[int] = None) -> None:
    self._context = context
    self._reporter = reporter
    self._sigs = sigs
    self._excludes = excludes
    self._max_graph_size = max_graph_size

  async def scan(self, q: Query) -> int:
    import asyncio
    from pubsub import pub
    from trueseeing.core.android.analysis.flow import DataFlows
    with DataFlows.apply_max_graph_size(self._max_graph_size):
      with self._apply_excludes_on_context():
        # XXX
        def _detected(issue: Issue) -> None:
          self._reporter.note(issue)
          q.issue_raise(issue)

        pub.subscribe(_detected, 'issue')
        await asyncio.gather(*[c(self._context).detect() for c in self._sigs])
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
