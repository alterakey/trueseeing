from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.core.store import Store
from trueseeing.core.ios.db import IPAStorePrep, IPAQuery

if TYPE_CHECKING:
  from sqlite3 import Connection

class IPAStore(Store):
  def _prep_schema(self, o: Connection, is_creating: bool) -> None:
    from trueseeing.core.db import FileTablePrep
    IPAStorePrep(o).stage0()
    if is_creating:
      FileTablePrep(o).prepare()
      IPAStorePrep(o).stage1()

  def _check_schema(self) -> None:
    IPAStorePrep(self.db).require_valid_schema()

  @classmethod
  def require_valid_schema_on(cls, path: str) -> None:
    import os.path
    store_path = os.path.join(path, cls._fn)
    if not os.path.exists(store_path):
      from trueseeing.core.exc import InvalidSchemaError
      raise InvalidSchemaError()
    else:
      import sqlite3
      o = sqlite3.connect(store_path)
      IPAStorePrep(o).require_valid_schema()

  def query(self) -> IPAQuery:
    return IPAQuery(store=self)
