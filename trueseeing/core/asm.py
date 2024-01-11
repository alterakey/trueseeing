from __future__ import annotations
from typing import TYPE_CHECKING
import os
import os.path

if TYPE_CHECKING:
  from typing import Tuple
  from trueseeing.core.context import Context

class APKDisassembler:
  _context: Context

  def __init__(self, context: Context, skip_resources: bool = False):
    self._context = context
    self._skip_resources = skip_resources

  @classmethod
  def _get_version(cls) -> str:
    from trueseeing import __version__
    return __version__

  def disassemble(self) -> None:
    self._do()
    self._context.store().prepare_schema()

  def _do(self) -> None:
    import sqlite3
    import glob
    import subprocess
    import shutil
    from trueseeing.core.literalquery import StorePrep, FileTablePrep, Query
    from trueseeing.core.tools import toolchains

    apk, archive = 'target.apk', 'store.db'

    cwd = os.getcwd()
    try:
      os.chdir(self._context.wd)
      c = sqlite3.connect(archive)
      query = Query(c=c)
      with c:
        StorePrep(c).stage0()
        FileTablePrep(c).prepare()

      with c:
        with toolchains() as tc:
          _ = subprocess.run('java -jar {apkeditor} d -i {apk} -o files'.format(
            apkeditor=tc['apkeditor'],
            apk=apk
          ), shell=True, capture_output=True)
          os.chdir('files')

        def read_as_row(fn: str) -> Tuple[str, bytes]:
          with open(fn, 'rb') as f:
            return fn, f.read()

        query.file_put_batch(read_as_row(fn) for fn in glob.glob('**', recursive=True) if os.path.isfile(fn))
        c.commit()
    finally:
      os.chdir(cwd)
      shutil.rmtree(os.path.join(self._context.wd, 'files'), ignore_errors=True)
