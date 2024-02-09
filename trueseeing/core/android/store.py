from __future__ import annotations
from typing import TYPE_CHECKING

import re
from trueseeing.core.android.db import Query

if TYPE_CHECKING:
  import sqlite3
  from typing import Any, AnyStr

class Store:
  db: sqlite3.Connection

  def __init__(self, path: str) -> None:
    self._path = path
    self.db = self._open_db()

  def _open_db(self) -> sqlite3.Connection:
    import os.path
    import sqlite3
    from trueseeing.core.android.db import StorePrep, FileTablePrep
    store_path = os.path.join(self._path, 'store.db')
    is_creating = not os.path.exists(store_path)
    o = sqlite3.connect(store_path)
    o.create_function("REGEXP", 2, Store._re_fn, deterministic=True)
    StorePrep(o).stage0()
    if is_creating:
      FileTablePrep(o).prepare()
      StorePrep(o).stage1()
    StorePrep(o).require_valid_schema()
    return o

  @staticmethod
  def require_valid_schema_on(path: str) -> None:
    import os.path
    import sqlite3
    from trueseeing.core.android.db import StorePrep
    store_path = os.path.join(path, 'store.db')
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

  def query(self) -> Query:
    return Query(store=self)
