from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.env import is_in_container
from trueseeing.core.ui import ui, FileTransferProgressReporter

if TYPE_CHECKING:
  from typing import Any, Optional, Literal, Dict
  from trueseeing.api import CommandHelper, Command, CommandMap, OptionMap

  ArchiveFormat = Optional[Literal['tar:', 'tar:gz']]

class AssembleCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return AssembleCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'ca':dict(e=self._assemble, n='ca[!] /path', d='assemble as target from path'),
      'ca!':dict(e=self._assemble),
      'cd':dict(e=self._disassemble, n='cd[s][!] /path', d='disassemble target into path'),
      'cd!':dict(e=self._disassemble),
      'cds':dict(e=self._disassemble_nodex),
      'cds!':dict(e=self._disassemble_nodex),
      'co':dict(e=self._export_context, n='co[!] /path [pat]', d='export codebase'),
      'co!':dict(e=self._export_context),
    }

  def get_options(self) -> OptionMap:
    return {
      'nocache':dict(n='nocache', d='do not replicate content before build [ca]')
    }

  async def _assemble(self, args: deque[str]) -> None:
    apk = self._helper.require_target('need target (i.e. output apk filename)')

    cmd = args.popleft()

    if not args:
      ui.fatal('need root path')

    import os
    import time
    from tempfile import TemporaryDirectory
    from trueseeing.core.android.asm import APKAssembler
    from trueseeing.core.android.tools import move_apk

    root = args.popleft()
    origapk = apk.replace('.apk', '.apk.orig')

    if os.path.exists(origapk) and not cmd.endswith('!'):
      ui.fatal('backup file exists; force (!) to overwrite')

    opts = self._helper.get_effective_options(self._helper.get_modifiers(args))

    ui.info('assembling {root} -> {apk}'.format(root=root, apk=apk))

    at = time.time()

    with TemporaryDirectory() as td:
      archive = self._deduce_archive_format(root)

      if not archive and opts.get('nocache', not is_in_container()):
        self._warn_if_container('nocache could be slow in container builds (try assembling from archives)')
        path = root
      else:
        path = os.path.join(td, 'f')

        if not archive:
          self._warn_if_container('caching massive files could be slow in container builds (try assembling from archives)')

        with FileTransferProgressReporter('caching content').scoped() as progress:
          if not archive:
            from trueseeing.core.tools import copytree
            for nr in copytree(os.path.join(root, '.'), path, divisor=(256 if progress.using_bar() else 1024)):
              progress.update(nr)
            progress.done()
          elif archive.startswith('tar'):
            from trueseeing.core.tools import copy_from_pack
            prefix = 'files'
            for nr in copy_from_pack(root, td, prefix=prefix, divisor=(256 if progress.using_bar() else 1024)):
              progress.update(nr)
            os.rename(os.path.join(td, prefix), path)
            progress.done()

      outapk, outsig = await APKAssembler.assemble_from_path(td, path)

      if os.path.exists(apk):
        move_apk(apk, origapk)

      move_apk(outapk, apk)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  def _warn_if_container(self, *args: Any, **kw: Any) -> None:
    from trueseeing.core.env import is_in_container
    if is_in_container():
      ui.warn(*args, **kw)

  async def _disassemble(self, args: deque[str], nodex: bool = False) -> None:
    apk = self._helper.require_target()

    cmd = args.popleft()

    if not args:
      ui.fatal('need output path')

    import os
    import time
    from shutil import rmtree
    from tempfile import TemporaryDirectory
    from trueseeing.core.android.asm import APKDisassembler
    from trueseeing.core.tools import move_as_output, pack_as_output

    path = args.popleft()

    if os.path.exists(path):
      if not cmd.endswith('!'):
        ui.fatal('output path exists; force (!) to overwrite')
      else:
        try:
          rmtree(path)
        except NotADirectoryError:
          os.remove(path)

    archive = self._deduce_archive_format(path)

    if not archive:
      self._warn_if_container('disassembling to directory could be slow in container builds (try disassembling to archives)')

    ui.info('disassembling {apk} -> {path}{nodex}'.format(apk=apk, path=path, nodex=' [res]' if nodex else ''))

    at = time.time()

    with TemporaryDirectory() as td:
      await APKDisassembler.disassemble_to_path(apk, td, nodex=nodex)

      if not archive:
        with FileTransferProgressReporter('disassemble: writing').scoped() as progress:
          for nr in move_as_output(td, path, allow_orphans=True):
            progress.update(nr)
          progress.done()
      elif archive.startswith('tar'):
        with FileTransferProgressReporter('disassemble: writing').scoped() as progress:
          for nr in pack_as_output(td, path, prefix='files', subformat=archive[4:], allow_orphans=True):
            progress.update(nr)
          progress.done()
        pass

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _disassemble_nodex(self, args: deque[str]) -> None:
    await self._disassemble(args, nodex=True)

  async def _export_context(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need path')

    root = args.popleft()
    ui.info('exporting target to {root}'.format(root=root))

    if args:
      pat = args.popleft()
    else:
      pat = None

    import os
    import time

    archive = self._deduce_archive_format(root)

    if not archive:
      self._warn_if_container('exporting to directory could be slow in container builds (try exporting to archives)')

    at = time.time()
    extracted = 0
    context = self._helper.get_context('apk')
    q = context.store().query()

    if not archive:
      for path,blob in q.file_enum(pat=pat, regex=True):
        target = os.path.join(root, *path.split('/'))
        if extracted % 10000 == 0:
          ui.info(' .. {nr} files'.format(nr=extracted))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'wb') as f:
          f.write(blob)
          extracted += 1
    elif archive.startswith('tar'):
      import tarfile
      from io import BytesIO
      kwargs: Dict[str, int] = dict()
      subformat = archive[4:]

      if subformat in ['gz']:
        kwargs.update(dict(compresslevel=3))

      with tarfile.open(root, 'w:{}'.format(subformat), **kwargs) as tf:  # type: ignore[arg-type]
        now = int(time.time())
        for path,blob in q.file_enum(pat=pat, regex=True):
          target = os.path.join('files', *path.split('/'))
          if extracted % 10000 == 0:
            ui.info(' .. {nr} files'.format(nr=extracted))

          bf = BytesIO(blob)
          ti = tarfile.TarInfo(name=target)
          ti.uname = 'root'
          ti.gname = 'root'
          ti.mode = 0o600
          ti.mtime = now
          tf.addfile(ti, fileobj=bf)
          extracted += 1

    ui.success('done: {nr} files ({t:.02f} sec.)'.format(nr=extracted, t=(time.time() - at)))

  def _deduce_archive_format(self, path: str) -> ArchiveFormat:
    if path.endswith('.tar'):
      return 'tar:'
    elif path.endswith('.tar.gz'):
      return 'tar:gz'
    else:
      return None
