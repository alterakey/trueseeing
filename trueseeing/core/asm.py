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

  async def disassemble(self, level: int = 3) -> None:
    await self._do(level)
    if level > 2:
      self._context.store().prepare_schema()

  async def _do(self, level: int) -> None:
    import sqlite3
    import glob
    import shutil
    from trueseeing.core.db import StorePrep, FileTablePrep, Query
    from trueseeing.core.tools import toolchains, invoke_streaming
    from trueseeing.core.ui import ui

    apk, archive = 'target.apk', 'store.db'

    cwd = os.getcwd()

    if ui.is_tty():
      import progressbar
      bar = progressbar.ProgressBar(widgets=[
        ui.bullet('info'),
        'analyze: disassembling... ',
        progressbar.RotatingMarker()   # type:ignore[no-untyped-call]
      ])
    else:
      bar = None

    try:
      os.chdir(self._context.wd)
      c = sqlite3.connect(archive)
      query = Query(c=c)
      StorePrep(c).stage0()
      FileTablePrep(c).prepare()

      with c:
        with toolchains() as tc:
          async for l in invoke_streaming(r'java -jar {apkeditor} d -i {apk} {suppressor} -o files'.format(
              apkeditor=tc['apkeditor'],
              apk=apk,
              suppressor='-dex' if level < 3 else '',
          ), redir_stderr=True):
            if bar is not None:
              bar.next()   # type:ignore[no-untyped-call]

          os.chdir('files')

        def read_as_row(fn: str) -> Tuple[str, bytes]:
          if bar is not None:
            bar.next()   # type:ignore[no-untyped-call]
          with open(fn, 'rb') as f:
            return fn, f.read()

        def should_cache(fn: str) -> bool:
          if not os.path.isfile(fn):
            return False
          if level < 2:
            return fn == 'AndroidManifest.xml'
          else:
            return True

        query.file_put_batch(read_as_row(fn) for fn in glob.glob('**', recursive=True) if should_cache(fn))
        if bar is not None:
          bar.next()   # type:ignore[no-untyped-call]
        c.commit()
    finally:
      os.chdir(cwd)
      if bar:
        bar.next()   # type:ignore[no-untyped-call]
      shutil.rmtree(os.path.join(self._context.wd, 'files'), ignore_errors=True)
      if bar:
        bar.finish(end='\r')   # type:ignore[no-untyped-call]

  @classmethod
  async def disassemble_to_path(cls, apk: str, path: str, nodex: bool = False) -> None:
    from trueseeing.core.tools import toolchains, invoke_streaming
    from trueseeing.core.ui import ui

    if ui.is_tty():
      import progressbar
      bar = progressbar.ProgressBar(widgets=[
        ui.bullet('info'),
        'disassemble: disassembling... ',
        progressbar.RotatingMarker()   # type:ignore[no-untyped-call]
      ])
    else:
      ui.info('disassemble: disassembling... ')
      bar = None

    with toolchains() as tc:
      async for l in invoke_streaming(
        '(java -jar {apkeditor} d -o {path} -i {apk} {s})'.format(
          apk=apk,
          s='-dex' if nodex else '',
          apkeditor=tc['apkeditor'],
          path=path,
        ), redir_stderr=True
      ):
        if bar is not None:
          bar.next()   # type:ignore[no-untyped-call]

    if bar is not None:
      ui.info('disassemble: disassembling... done.', ow=True)
    else:
      ui.info('disassemble: done')

class APKAssembler:
  @classmethod
  async def assemble_from_path(cls, wd: str, path: str) -> Tuple[str, str]:
    import os
    from trueseeing.core.sign import SigningKey
    from trueseeing.core.tools import invoke_streaming, toolchains
    from trueseeing.core.ui import ui

    if ui.is_tty():
      import progressbar
      bar = progressbar.ProgressBar(widgets=[
        ui.bullet('info'),
        'assemble: assembling... ',
        progressbar.RotatingMarker()   # type:ignore[no-untyped-call]
      ])
    else:
      ui.info('assemble: assembling... ')
      bar = None

    with toolchains() as tc:
      async for l in invoke_streaming(
        '(java -jar {apkeditor} b -i {path} -o {wd}/output.apk && java -jar {apksigner} sign --ks {keystore} --ks-pass pass:android {wd}/output.apk)'.format(
          wd=wd, path=path,
          apkeditor=tc['apkeditor'],
          apksigner=tc['apksigner'],
          keystore=await SigningKey().key(),
        ), redir_stderr=True
      ):
        if bar is not None:
          bar.next()  # type:ignore[no-untyped-call]

    if bar is not None:
      ui.info('assemble: assembling... done.', ow=True)
    else:
      ui.info('assemble: done')

    return os.path.join(wd, 'output.apk'), os.path.join(wd, 'output.apk.idsig')
