from __future__ import annotations
from typing import TYPE_CHECKING

import os
import os.path

from pubsub import pub

from trueseeing.core.env import get_home_dir
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Tuple, Optional
  from trueseeing.core.context import Context
  from trueseeing.core.db import FileEntry

class APKDisassembler:
  _context: Context

  def __init__(self, context: Context, target: Optional[str] = None):
    self._context = context
    if target:
      self._target = target
    else:
      self._target = context.target

  async def disassemble(self, level: int = 4) -> None:
    await self._do(level)

  async def _do(self, level: int) -> None:
    import glob
    import shutil
    from shlex import quote
    from trueseeing.core.tools import invoke_streaming
    from trueseeing.core.android.tools import toolchains

    cwd = os.getcwd()

    pub.sendMessage('progress.core.asm.lift.begin')

    try:
      os.chdir(self._context.wd)

      with self._context.store().query().scoped() as query:
        with toolchains() as tc:
          async for l in invoke_streaming(r'java -jar {apkeditor} d -i {apk} {suppressor} -o files'.format(
              apkeditor=tc['apkeditor'],
              apk=quote(self._target),
              suppressor='-dex' if level < 3 else '',
          ), redir_stderr=True):
            pub.sendMessage('progress.core.asm.lift.update')

          os.chdir('files')

        def read_as_row(fn: str) -> FileEntry:
          pub.sendMessage('progress.core.asm.lift.update')
          with open(fn, 'rb') as f:
            return dict(path=fn, blob=f.read(), z=True)

        def should_cache(fn: str) -> bool:
          if not os.path.isfile(fn):
            return False
          if level < 2:
            return fn == 'AndroidManifest.xml'
          else:
            return True

        query.file_put_batch(read_as_row(fn) for fn in glob.glob('**', recursive=True) if should_cache(fn))
        pub.sendMessage('progress.core.asm.lift.update')
    finally:
      os.chdir(cwd)
      pub.sendMessage('progress.core.asm.lift.update')
      shutil.rmtree(os.path.join(self._context.wd, 'files'), ignore_errors=True)
      pub.sendMessage('progress.core.asm.lift.done')

  @classmethod
  async def disassemble_to_path(cls, target: str, path: str, nodex: bool = False, merge: bool = False) -> None:
    import os
    from shlex import quote
    from tempfile import TemporaryDirectory
    from trueseeing.core.tools import invoke_streaming
    from trueseeing.core.android.tools import toolchains

    pub.sendMessage('progress.core.asm.disasm.begin')

    with TemporaryDirectory() as td:
      with toolchains() as tc:
        apk = target
        if target.endswith('.xapk'):
          if not merge:
            raise ValueError('cannot disassemble xapk without merging')
          with TemporaryDirectory() as td2:
            from zipfile import ZipFile
            with ZipFile(target) as zf:
              for n in zf.namelist():
                zf.extract(n, path=td2)
            tmpapk = os.path.join(td, 'merged.apk')
            async for l in invoke_streaming(
              '(java -jar {apkeditor} m -i {path} -o {tmpapk})'.format(
                apkeditor=tc['apkeditor'],
                path=td2,
                tmpapk=tmpapk,
              )
            ):
              print(l)
          apk = tmpapk
        else:
          apk = target

      async for l in invoke_streaming(
        '(java -jar {apkeditor} d -o {path} -i {apk} {s})'.format(
          apk=quote(apk),
          s='-dex' if nodex else '',
          apkeditor=tc['apkeditor'],
          path=quote(path),
        ), redir_stderr=True
      ):
        pub.sendMessage('progress.core.asm.disasm.update')

    pub.sendMessage('progress.core.asm.disasm.done')

class APKAssembler:
  @classmethod
  async def assemble_from_path(cls, wd: str, path: str) -> Tuple[str, str]:
    import os
    from shlex import quote
    from trueseeing.core.tools import invoke_streaming
    from trueseeing.core.android.tools import toolchains

    pub.sendMessage('progress.core.asm.asm.begin')

    with toolchains() as tc:
      async for l in invoke_streaming(
        '(java -jar {apkeditor} b -i {path} -o {wd}/output.apk && java -jar {apksigner} sign --ks {keystore} --ks-pass pass:android {wd}/output.apk)'.format(
          wd=quote(wd), path=quote(path),
          apkeditor=tc['apkeditor'],
          apksigner=tc['apksigner'],
          keystore=await SigningKey().key(),
        ), redir_stderr=True
      ):
        pub.sendMessage('progress.core.asm.asm.update')

    pub.sendMessage('progress.core.asm.asm.done')

    return os.path.join(wd, 'output.apk'), os.path.join(wd, 'output.apk.idsig')

  @classmethod
  async def merge_slices(cls, xapk: str, wd: str) -> Tuple[str, str]:
    import os
    from shlex import quote
    from trueseeing.core.tools import invoke_streaming
    from trueseeing.core.android.tools import toolchains

    pub.sendMessage('progress.core.asm.asm.begin')

    with toolchains() as tc:
      async for l in invoke_streaming(
        'java -jar {apkeditor} m -i {xapk} -o {wd}/output.apk'.format(
          wd=wd, xapk=quote(xapk),
          apkeditor=tc['apkeditor'],
        ), redir_stderr=True
      ):
        pub.sendMessage('progress.core.asm.asm.update')

    pub.sendMessage('progress.core.asm.asm.done')

    return os.path.join(wd, 'output.apk'), os.path.join(wd, 'output.apk.idsig')

class SigningKey:
  _path: str

  def __init__(self) -> None:
    self._path = os.path.join(get_home_dir(), 'sign.keystore')

  async def key(self) -> str:
    os.makedirs(os.path.dirname(self._path), exist_ok=True)
    if not os.path.exists(self._path):
      await self._generate()
    return self._path

  async def _generate(self) -> None:
    from shlex import quote
    from trueseeing.core.tools import invoke_passthru
    ui.info("generating key for repackaging")
    await invoke_passthru(f'keytool -genkey -v -keystore {quote(self._path)} -alias androiddebugkey -dname "CN=Android Debug, O=Android, C=US" -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000')
