from __future__ import annotations
from typing import TYPE_CHECKING

import os.path
import re
import zstandard as zstd
from trueseeing.core.db import Query

if TYPE_CHECKING:
  from typing import Any, AnyStr, Final
  from sqlite3 import Connection

class Store:
  _fn: Final[str] = 'store.db'
  db: Connection

  def __init__(self, path: str) -> None:
    self._path = path
    self.db = self._open_db()
    self._check_schema()

  def _open_db(self) -> Connection:
    import sqlite3
    store_path = os.path.join(self._path, self._fn)
    is_creating = not os.path.exists(store_path)
    o = sqlite3.connect(store_path)
    o.create_function("REGEXP", 2, self._re_fn, deterministic=True)
    o.create_function("MZD", 2, self._mzd_fn, deterministic=True)
    o.create_function("MZE", 2, self._mze_fn, deterministic=True)
    self._prep_schema(o, is_creating)
    return o

  def _prep_schema(self, o: Connection, is_creating: bool) -> None:
    from trueseeing.core.db import StorePrep, FileTablePrep
    StorePrep(o).stage0()
    if is_creating:
      FileTablePrep(o).prepare()
      StorePrep(o).stage1()

  def _check_schema(self) -> None:
    from trueseeing.core.db import StorePrep
    StorePrep(self.db).require_valid_schema()

  @classmethod
  def require_valid_schema_on(cls, path: str) -> None:
    import os.path
    import sqlite3
    from trueseeing.core.db import StorePrep
    store_path = os.path.join(path, cls._fn)
    if not os.path.exists(store_path):
      from trueseeing.core.exc import InvalidSchemaError
      raise InvalidSchemaError()
    else:
      o = sqlite3.connect(store_path)
      StorePrep(o).require_valid_schema()

  @staticmethod
  def _re_fn(expr: AnyStr, item: Any) -> bool:
    if item is not None:
      return re.compile(expr).search(item) is not None
    else:
      return False

  @staticmethod
  def _mzd_fn(z: bool, item: bytes) -> bytes:
    if not z:
      return item
    else:
      return zstd.ZstdDecompressor().decompress(item)

  @staticmethod
  def _mze_fn(z: bool, item: bytes) -> bytes:
    if not z:
      return item
    else:
      return zstd.ZstdCompressor(threads=-1).compress(item)

  def query(self) -> Query:
    return Query(store=self)
