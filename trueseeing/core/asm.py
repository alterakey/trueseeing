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
    from pkg_resources import get_distribution
    return get_distribution('trueseeing').version

  def disassemble(self) -> None:
    self._do()
    self._context.store().prepare_schema()

  def _do(self) -> None:
    import sqlite3
    import glob
    import subprocess
    import pkg_resources
    import shutil
    from trueseeing.core.literalquery import StorePrep

    apk, archive = 'target.apk', 'store.db'

    cwd = os.getcwd()
    try:
      os.chdir(self._context.wd)
      c = sqlite3.connect(archive)
      with c:
        StorePrep(c).stage0()
        c.execute('drop table if exists files')
        c.execute('create table files(path text not null unique, blob bytes not null)')

      with c:
        _ = subprocess.run('java -jar {apkeditor} d -i {apk} -o files'.format(
          apkeditor=pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'apkeditor.jar')),
          apk=apk
        ), shell=True, capture_output=True)
        os.chdir('files')

        def read_as_row(fn: str) -> Tuple[str, bytes]:
          with open(fn, 'rb') as f:
            return fn, f.read()

        c.executemany('insert into files (path, blob) values (?,?)', (read_as_row(fn) for fn in glob.glob('**', recursive=True) if os.path.isfile(fn)))
        c.commit()
    finally:
      os.chdir(cwd)
      shutil.rmtree(os.path.join(self._context.wd, 'files'), ignore_errors=True)
