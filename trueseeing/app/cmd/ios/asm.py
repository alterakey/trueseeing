from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.env import is_in_container
from trueseeing.core.ui import ui

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
      'co':dict(e=self._export_context, n='co[!] /path [pat]', d='export codebase', t={'ipa'}),
      'co!':dict(e=self._export_context, t={'ipa'}),
    }

  def get_options(self) -> OptionMap:
    return dict()

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
    context = self._helper.get_context()
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

      with tarfile.open(root, 'w:{}'.format(subformat), **kwargs) as tf:  # type: ignore[call-overload]
        now = int(time.time())
        for path,blob in q.file_enum(pat=pat, regex=True):
          target = os.path.join('files', *path.split('/'))
          if extracted % 10000 == 0:
            ui.info(' .. {nr} files'.format(nr=extracted))

          bf = BytesIO(blob)
          ti = tarfile.TarInfo(name=target)
          ti.size = len(blob)
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

  def _warn_if_container(self, *args: Any, **kw: Any) -> None:
    if is_in_container():
      ui.warn(*args, **kw)
