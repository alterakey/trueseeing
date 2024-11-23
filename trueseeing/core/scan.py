from __future__ import annotations
from typing import TYPE_CHECKING

from contextlib import contextmanager

if TYPE_CHECKING:
  from typing import List, Optional, Iterator, Dict, Any, Set
  from trueseeing.api import SignatureEntry, SignatureHelper, SignatureMap
  from trueseeing.core.context import Context, ContextType
  from trueseeing.core.db import Query
  from trueseeing.core.model.issue import Issue, IssueConfidence

class Scanner:
  _helper: SignatureHelper
  _sigs: Dict[str, SignatureEntry]

  def __init__(self, context: Context, *, sigsels: List[str] = [], excludes: List[str] = [], max_graph_size: Optional[int] = None) -> None:
    from trueseeing.core.config import Configs
    self._context = context
    self._sigs = dict()
    self._excludes = excludes
    self._max_graph_size = max_graph_size
    self._confbag = Configs.get().bag
    self._helper = SignatureHelperImpl(self)

    self._init_sigs(['all'] + sigsels)

  def get_active_signatures(self) -> SignatureMap:
    return self._sigs

  @classmethod
  def get_all_signatures(cls) -> SignatureMap:
    return Scanner(context=None).get_active_signatures()  # type: ignore[arg-type]

  async def scan(self, q: Query) -> int:
    import asyncio
    from pubsub import pub
    from trueseeing.core.exc import InvalidContextError
    from trueseeing.core.android.analyze.flow import DataFlow
    from trueseeing.core.ui import ui
    with DataFlow.apply_max_graph_size(self._max_graph_size):
      with self._apply_excludes_on_context():
        def _detected(issue: Issue) -> None:
          q.issue_raise(issue)

        async def _call(id_: str, ent: SignatureEntry) -> None:
          try:
            await ent['e']()
          except InvalidContextError:
            ui.warn(f'scan: {id_}: context invalid, signature ignored')

        pub.subscribe(_detected, 'issue')
        await asyncio.gather(*[_call(k, v) for k,v in self._sigs.items()])
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
    def _match(sigid: str, sel: str) -> Optional[bool]:
      neg = False
      if sel.startswith('no-'):
        sel = sel[3:]
        neg = True
      if sel == 'all':
        return not neg
      elif sel.endswith('-all'):
        psel = sel[:-4]
        if sigid.startswith(psel):
          return not neg
        else:
          return None
      else:
        if sigid == sel:
          return not neg
        else:
          return None
    for o in (_match(sigid, x) for x in reversed(sels)):
      if o is None:
        continue
      return o
    else:
      return False

  def _require_sigsels_fully_applied(self, sigsels: List[str], known: Set[str]) -> None:
    def _regen(key: str, neg: bool) -> str:
      return ('no-' if neg else '') + key
    unknown = set()
    for sel in set(sigsels):
      neg = False
      if sel.startswith('no-'):
        sel = sel[3:]
        neg = True
      if sel != 'all':
        if sel.endswith('-all'):
          psel = sel[:-4]
          if psel and not any((f'{psel}-' in k) for k in known):
            unknown.add(_regen(sel, neg))
        elif sel not in known:
          unknown.add(_regen(sel, neg))
    if unknown:
      raise ValueError(unknown)

  def _init_sigs(self, sigsels: List[str]) -> None:
    from itertools import chain
    from trueseeing.sig import discover
    from trueseeing.core.ext import Extension
    known = set()
    for clazz in chain(discover(), Extension.get().get_signatures()):
      matched = False
      t = clazz.create(self._helper)
      for k,v in t.get_sigs().items():
        known.add(k)
        if self._sigsel_matches(k, sigsels):
          self._sigs[k] = v
          matched = True
      if matched:
        self._confbag.update(t.get_configs())
    self._require_sigsels_fully_applied(sigsels, known)

class SignatureHelperImpl:
  def __init__(self, scanner: Scanner) -> None:
    self._s = scanner
    self._confbag = self._s._confbag
  def get_context(self, typ: Optional[ContextType] = None) -> Any:
    if typ:
      from trueseeing.core.ui import ui
      ui.warn('get_context(typ): deprecated, use get_context().request_type(...)', onetime=True)
      self._s._context.require_type(typ)
    return self._s._context
  def raise_issue(self, issue: Issue) -> None:
    from pubsub import pub
    pub.sendMessage('issue', issue=issue)
  def build_issue(
      self,
      sigid: str,
      cvss: str,
      title: str,
      cfd: IssueConfidence = 'firm',
      summary: Optional[str] = None,
      desc: Optional[str] = None,
      ref: Optional[str] = None,
      sol: Optional[str] = None,
      info0: Optional[str] = None,
      info1: Optional[str] = None,
      info2: Optional[str] = None,
      aff0: Optional[str] = None,
      aff1: Optional[str] = None,
      aff2: Optional[str] = None,
  ) -> Issue:
    from trueseeing.core.model.issue import Issue
    return Issue(
      sigid=sigid,
      cvss=cvss,
      cfd=cfd,
      title=title,
      desc=desc,
      ref=ref,
      sol=sol,
      summary=summary,
      info0=info0,
      info1=info1,
      info2=info2,
      aff0=aff0,
      aff1=aff1,
      aff2=aff2,
    )
  def get_config(self, k: str) -> Any:
    from trueseeing.core.exc import InvalidConfigKeyError
    try:
      e = self._confbag[k]
    except KeyError:
      raise InvalidConfigKeyError()
    else:
      return e['g']()

  def set_config(self, k: str, v: Any) -> None:
    from trueseeing.core.exc import InvalidConfigKeyError
    try:
      e = self._confbag[k]
    except KeyError:
      raise InvalidConfigKeyError()
    else:
      e['s'](v)
