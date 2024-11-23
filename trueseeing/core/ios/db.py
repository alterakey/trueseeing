from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.core.db import Query, StorePrep
from trueseeing.core.z import zd

if TYPE_CHECKING:
  from typing import Optional, Iterator, Iterable, Tuple
  from trueseeing.core.ios.model import Call

class IPAStorePrep(StorePrep):
  def stage1(self) -> None:
    super().stage1()
    from importlib.resources import files
    self.c.executescript((files('trueseeing')/'libs'/'ios'/'store.0.sql').read_text())

  def stage2(self) -> None:
    from importlib.resources import files
    self.c.executescript((files('trueseeing')/'libs'/'ios'/'store.1.sql').read_text())

  def _get_cache_schema_id(self) -> int:
    return super()._get_cache_schema_id() ^ 0x00f28883

class IPAQuery(Query):
  def file_enum(self, pat: Optional[str], patched: bool = False, regex: bool = False, neg: bool = False) -> Iterable[Tuple[str, bytes]]:
    if pat is not None:
      stmt0 = 'select path, z, blob from files where {neg} path {op} :pat'.format(neg='not' if neg else '', op=('like' if not regex else 'regexp'))
      stmt1 = 'select path, A.z as z, coalesce(B.blob, A.blob) as blob from files as A full outer join patches as B using (path) where path {op} :pat'.format(op=('like' if not regex else 'regexp'))
      for n, z, o in self.db.execute(stmt1 if patched else stmt0, dict(pat=pat)):
        yield n, zd(o) if z else o
    else:
      stmt2 = 'select path, z, blob from files'
      stmt3 = 'select path, A.z as z, coalesce(B.blob, A.blob) from files as A full outer join patches as B using (path)'
      for n, z, o in self.db.execute(stmt3 if patched else stmt2):
        yield n, zd(o) if z else o

  def call_add_batch(self, gen: Iterator[Call]) -> None:
    stmt0 = 'insert into ncalls (priv, swift, cpp, objc, target, path, sect, offs) values (:priv, :swift, :cpp, :objc, :target, :path, :sect, :offs)'
    self.db.executemany(stmt0, gen)

  def call_count(self) -> int:
    stmt0 = 'select count(1) from ncalls'
    for n, in self.db.execute(stmt0):
      return n # type:ignore[no-any-return]
    return 0

  def calls(self, priv: bool = False, api: bool = False) -> Iterator[Call]:
    stmt0 = 'select priv, swift, cpp, objc, target, path, sect, offs from ncalls'
    stmt1 = 'select priv, swift, cpp, objc, target, path, sect, offs from ncalls where priv=:is_priv'
    for priv, swift, cpp, objc, target, path, sect, offs in self.db.execute(stmt1 if (priv or api) else stmt0, dict(is_priv=priv)):
      yield dict(
        path=path,
        sect=sect,
        offs=offs,
        priv=priv,
        swift=swift,
        objc=objc,
        cpp=cpp,
        target=target,
      )
