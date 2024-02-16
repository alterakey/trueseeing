from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.core.store import Store
from trueseeing.core.android.db import APKQuery

if TYPE_CHECKING:
  from sqlite3 import Connection

class APKStore(Store):
  def _prep_schema(self, o: Connection, is_creating: bool) -> None:
    from trueseeing.core.db import FileTablePrep
    from trueseeing.core.android.db import APKStorePrep
    APKStorePrep(o).stage0()
    if is_creating:
      FileTablePrep(o).prepare()
      APKStorePrep(o).stage1()

  def _check_schema(self) -> None:
    from trueseeing.core.android.db import APKStorePrep
    APKStorePrep(self.db).require_valid_schema()

  @classmethod
  def require_valid_schema_on(cls, path: str) -> None:
    import os.path
    store_path = os.path.join(path, cls._fn)
    if not os.path.exists(store_path):
      from trueseeing.core.exc import InvalidSchemaError
      raise InvalidSchemaError()
    else:
      import sqlite3
      from trueseeing.core.android.db import APKStorePrep
      o = sqlite3.connect(store_path)
      APKStorePrep(o).require_valid_schema()

  def query(self) -> APKQuery:
    return APKQuery(store=self)
