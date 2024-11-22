from __future__ import annotations
from typing import TYPE_CHECKING

from contextlib import contextmanager
from trueseeing.core.model.issue import Issue
from trueseeing.core.tools import noneif
from trueseeing.core.z import ze, zd

if TYPE_CHECKING:
  from typing import Any, Iterable, Tuple, Optional, Iterator, List, TypedDict
  from typing_extensions import Self
  from sqlite3 import Connection
  from trueseeing.core.store import Store
  from trueseeing.core.model.issue import IssueConfidence

  class FileEntry(TypedDict):
    path: str
    blob: bytes
    z: bool

class StorePrep:
  def __init__(self, c: Connection) -> None:
    self.c = c

  def stage0(self) -> None:
    from importlib.resources import files
    self.c.executescript((files('trueseeing')/'libs'/'store.s.sql').read_text())

  def stage1(self) -> None:
    from importlib.resources import files
    self.c.execute('pragma user_version={}'.format(self._get_cache_schema_id()))
    self.c.executescript((files('trueseeing')/'libs'/'store.0.sql').read_text())

  def require_valid_schema(self) -> None:
    v, = self.c.execute('pragma user_version').fetchone()
    if v != self._get_cache_schema_id():
      from trueseeing.core.exc import InvalidSchemaError
      raise InvalidSchemaError()

  def _get_cache_schema_id(self) -> int:
    from trueseeing.core.env import get_cache_schema_id
    return get_cache_schema_id()

class FileTablePrep:
  def __init__(self, c: Connection) -> None:
    self.c = c

  def prepare(self) -> None:
    from importlib.resources import files
    self.c.executescript((files('trueseeing')/'libs'/'files.0.sql').read_text())

class Query:
  def __init__(self, store: Store) -> None:
    self.db = store.db

  @contextmanager
  def scoped(self) -> Iterator[Self]:
    with self.db:
      yield self

  def file_find(self, pat: str, regex: bool = False) -> Iterable[str]:
    for f, in self.db.execute('select path from files where path {op} :pat'.format(op=('like' if not regex else 'regexp')), dict(pat=pat)):
      yield f

  def file_get(self, path: str, default: Optional[bytes] = None, patched: bool = False) -> Optional[bytes]:
    b: bytes
    stmt0 = 'select z, blob from files where path=:path'
    stmt1 = 'select A.z as z,coalesce(B.blob, A.blob) as blob from files as A full outer join patches as B using (path) where path=:path'
    for z, b in self.db.execute(stmt1 if patched else stmt0, dict(path=path)):
      return zd(b) if z else b
    else:
      return default

  def file_get_xml(self, path: str, default: Any = None, patched: bool = False) -> Any:
    import lxml.etree as ET
    r = self.file_get(path, patched=patched)
    if r is not None:
      return ET.fromstring(r, parser=ET.XMLParser(recover=True))
    else:
      return default

  def file_enum(self, pat: Optional[str], patched: bool = False, regex: bool = False, neg: bool = False) -> Iterable[Tuple[str, bytes]]:
    if pat is not None:
      stmt0 = 'select path, z, blob from files where {neg} path {op} :pat'.format(neg='not' if neg else '', op=('like' if not regex else 'regexp'))
      stmt1 = 'select path, coalesce(B.z, A.z) as z, coalesce(B.blob, A.blob) as blob from files as A full outer join patches as B using (path) where {neg} path {op} :pat'.format(neg='not' if neg else '', op=('like' if not regex else 'regexp'))
      for n, z, o in self.db.execute(stmt1 if patched else stmt0, dict(pat=pat)):
        yield n, zd(o) if z else o
    else:
      stmt2 = 'select path, z, blob from files'
      stmt3 = 'select path, coalesce(B.z, A.z) as z, coalesce(B.blob, A.blob) from files as A full outer join patches as B using (path)'
      for n, z, o in self.db.execute(stmt3 if patched else stmt2):
        yield n, zd(o) if z else o

  def file_count(self, pat: Optional[str], patched: bool = False, regex: bool = False, neg: bool = False) -> int:
    if pat is not None:
      stmt0 = 'select count(1) from files where {neg} path {op} :pat'.format(neg='not' if neg else '', op=('like' if not regex else 'regexp'))
      stmt1 = 'select conut(1) from files as A full outer join patches as B using (path) where {neg} path {op} :pat'.format(neg='not' if neg else '', op=('like' if not regex else 'regexp'))
      for nr, in self.db.execute(stmt1 if patched else stmt0, dict(pat=pat)):
        return nr # type:ignore[no-any-return]
    else:
      stmt2 = 'select count(1) from files'
      stmt3 = 'select count(1) from files as A full outer join patches as B using (path)'
      for nr, in self.db.execute(stmt3 if patched else stmt2):
        return nr # type:ignore[no-any-return]
    return 0

  def file_put_batch(self, gen: Iterable[FileEntry]) -> None:
    self.db.executemany(
      'insert into files (path, blob, z) values (:path,:blob,:z)',
      (dict(path=e['path'], blob=ze(e['blob']) if e['z'] else e['blob'], z=e['z']) for e in gen)
    )

  def patch_enum(self, pat: Optional[str]) -> Iterable[Tuple[str, bytes]]:
    if pat is not None:
      stmt0 = 'select path, z, blob from patches where path like :pat'
      for n, z, o in self.db.execute(stmt0, dict(pat=pat)):
        yield n, zd(o) if z else o
    else:
      stmt1 = 'select path, z, blob from patches'
      for n, z, o in self.db.execute(stmt1):
        yield n, zd(o) if z else o

  def patch_put(self, path: str, blob: bytes, z: bool) -> None:
    self.db.execute(
      'replace into patches (path, blob, z) values (:path,:blob,:z)',
      dict(path=path, blob=ze(blob) if z else blob, z=z)
    )

  def patch_exists(self, path: Optional[str]) -> bool:
    stmt0 = 'select 1 from patches where path=:path'
    stmt1 = 'select 1 from patches'
    for r, in self.db.execute(stmt0 if path is not None else stmt1, dict(path=path)):
      return True
    else:
      return False

  def patch_clear(self) -> None:
    self.db.execute('delete from patches')

  def issue_count(self) -> int:
    for nr, in self.db.execute('select count(1) from analysis_issues'):
      return int(nr)
    else:
      return 0

  def issue_raise(self, i: Issue) -> None:
    assert i.score is not None
    self.db.execute(
      'insert or ignore into analysis_issues (sig, title, summary, descr, ref, sol, info0, info1, info2, cfd, score, cvss, aff0, aff1, aff2) values (:sigid, :title, :summary, :desc, :ref, :sol, :info0, :info1, :info2, :cfd, :score, :cvss, :aff0, :aff1, :aff2)',
      dict(
        sigid=i.sigid,
        title=i.title,
        cfd=self._issue_confidence_to_int(i.cfd),
        cvss=i.cvss,
        score=i.score,
        summary=noneif(i.summary, ''),
        desc=noneif(i.desc, ''),
        ref=noneif(i.ref, ''),
        sol=noneif(i.sol, ''),
        info0=noneif(i.info0, ''),
        info1=noneif(i.info1, ''),
        info2=noneif(i.info2, ''),
        aff0=noneif(i.aff0, ''),
        aff1=noneif(i.aff1, ''),
        aff2=noneif(i.aff2, ''),
      ))

  def issue_clear(self) -> None:
    self.db.execute('delete from analysis_issues')

  def issues(self) -> Iterable[Issue]:
    for m in self.db.execute('select sig, title, summary, descr, ref, sol, info0, info1, info2, cfd, score, cvss, aff0, aff1, aff2 from analysis_issues'):
      yield self._issue_from_row(m)

  def findings_list(self) -> Iterable[Tuple[int, Tuple[str, str, Optional[str], Optional[str], Optional[str], Optional[str], float, str]]]:
    for no, r in enumerate(self.db.execute('select distinct sig, title, summary, descr, ref, sol, score, cvss from analysis_issues order by score desc')):
      yield no, (
        r[0],
        r[1],
        r[2] if r[2] else None,
        r[3] if r[3] else None,
        r[4] if r[4] else None,
        r[5] if r[5] else None,
        r[6],
        r[7],
      )

  def issues_by_group(self, *, sig: str, title: str) -> Iterable[Issue]:
    for m in self.db.execute('select sig, title, summary, descr, ref, sol, info0, info1, info2, cfd, score, cvss, aff0, aff1, aff2 from analysis_issues where sig=:sig and title=:title order by score desc, cfd desc', dict(sig=sig, title=title)):
      yield self._issue_from_row(m)

  @classmethod
  def _issue_confidence_to_int(cls, c: IssueConfidence) -> int:
    return dict(certain=2, firm=1, tentative=0)[c]

  @classmethod
  def _issue_confidence_from_int(cls, c: int) -> IssueConfidence:
    m: List[IssueConfidence] = ['tentative', 'firm', 'certain']
    return m[c]

  @classmethod
  def _issue_from_row(cls, r: Tuple[Any, ...]) -> Issue:
    return Issue(
      sigid=r[0],
      title=r[1],
      cfd=cls._issue_confidence_from_int(r[9]),
      cvss=r[11],
      summary=r[2] if r[2] else None,
      desc=r[3] if r[3] else None,
      ref=r[4] if r[4] else None,
      sol=r[5] if r[5] else None,
      info0=r[6] if r[6] else None,
      info1=r[7] if r[7] else None,
      info2=r[8] if r[8] else None,
      aff0=r[12] if r[12] else None,
      aff1=r[13] if r[13] else None,
      aff2=r[14] if r[14] else None,
    )
