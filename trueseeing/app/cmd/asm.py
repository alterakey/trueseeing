from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import Command
from trueseeing.core.env import is_in_container
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Dict
  from trueseeing.app.inspect import Runner
  from trueseeing.core.model.cmd import CommandEntry, OptionEntry

class AssembleCommand(Command):
  _runner: Runner

  def __init__(self, runner: Runner) -> None:
    self._runner = runner

  def get_commands(self) -> Dict[str, CommandEntry]:
    return {
      'ca':dict(e=self._assemble, n='ca[!] /path', d='assemble as target from path'),
      'ca!':dict(e=self._assemble),
      'cd':dict(e=self._disassemble, n='cd[s][!] /path', d='disassemble target into path'),
      'cd!':dict(e=self._disassemble),
      'cds':dict(e=self._disassemble),
      'cds!':dict(e=self._disassemble),
      'cf':dict(e=self._use_framework, n='cf framework.apk', d='use framework'),
      'co':dict(e=self._export_context, n='co[!] /path [pat]', d='export codebase'),
      'co!':dict(e=self._export_context),
    }

  def get_options(self) -> Dict[str, OptionEntry]:
    return {
      'nocache':dict(n='nocache', d='do not replicate content before build [ca]')
    }

  async def _assemble(self, args: deque[str]) -> None:
    self._runner._require_target('need target (i.e. output apk filename)')
    assert self._runner._target is not None

    cmd = args.popleft()

    if not args:
      ui.fatal('need root path')

    import os
    import time
    from tempfile import TemporaryDirectory
    from trueseeing.core.asm import APKAssembler
    from trueseeing.core.tools import move_apk, copytree

    root = args.popleft()
    apk = self._runner._target
    origapk = apk.replace('.apk', '.apk.orig')

    if os.path.exists(origapk) and not cmd.endswith('!'):
      ui.fatal('backup file exists; force (!) to overwrite')

    opts = self._runner._get_effective_options(self._runner._get_modifiers(args))

    ui.info('assembling {root} -> {apk}'.format(root=root, apk=apk))

    at = time.time()

    with TemporaryDirectory() as td:
      if opts.get('nocache', 0 if is_in_container() else 1):
        path = root
      else:
        if ui.is_tty():
          import progressbar
          bar = progressbar.ProgressBar(widgets=[
            ui.bullet('info'),
            'caching content... ',
            progressbar.Counter(), ' ',   # type:ignore[no-untyped-call]
            progressbar.RotatingMarker()   # type:ignore[no-untyped-call]
          ])
          bar.start() # type:ignore[no-untyped-call]
        else:
          ui.info('caching content')
          bar = None

        path = os.path.join(td, 'f')
        for nr in copytree(os.path.join(root, '.'), path, divisor=(256 if bar else 1024)):
          if bar is not None:
            bar.update(nr) # type: ignore[no-untyped-call]
          else:
            ui.info(f' .. {nr} files')
        if bar is not None:
          bar.finish()  # type: ignore[no-untyped-call]

      outapk, outsig = await APKAssembler.assemble_from_path(td, path)

      if os.path.exists(apk):
        move_apk(apk, origapk)

      move_apk(outapk, apk)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _disassemble(self, args: deque[str]) -> None:
    self._runner._require_target()
    assert self._runner._target is not None

    cmd = args.popleft()

    if not args:
      ui.fatal('need output path')

    import os
    import time
    from shutil import rmtree
    from tempfile import TemporaryDirectory
    from trueseeing.core.asm import APKDisassembler
    from trueseeing.core.tools import move_as_output

    path = args.popleft()
    apk = self._runner._target

    if os.path.exists(path):
      if not cmd.endswith('!'):
        ui.fatal('output path exists; force (!) to overwrite')
      else:
        rmtree(path)

    ui.info('disassembling {apk} -> {path}'.format(apk=apk, path=path))

    at = time.time()

    with TemporaryDirectory() as td:
      await APKDisassembler.disassemble_to_path(apk, td)

      if ui.is_tty():
        import progressbar
        bar = progressbar.ProgressBar(widgets=[
          ui.bullet('info'),
          'disassemble: writing... ',
          progressbar.Counter(), ' ',   # type:ignore[no-untyped-call]
          progressbar.RotatingMarker()   # type:ignore[no-untyped-call]
        ])
        bar.start() # type:ignore[no-untyped-call]
      else:
        bar = None

      for nr in move_as_output(td, path, allow_orphans=True):
        if bar is not None:
          bar.update(nr) # type:ignore[no-untyped-call]

      ui.info('disassemble: writing... done.' + (' '*16), ow=True)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _use_framework(self, args: deque[str]) -> None:
    _ = args.popleft()

    if not args:
      ui.fatal('need framework apk')

    from trueseeing.core.tools import invoke_passthru
    from importlib.resources import as_file, files

    apk = args.popleft()

    with as_file(files('trueseeing')/'libs'/'apktool.jar') as path:
      await invoke_passthru(
        'java -jar {apktool} if {apk}'.format(
          apk=apk,
          apktool=path,
        ))

  async def _export_context(self, args: deque[str]) -> None:
    self._runner._require_target()
    assert self._runner._target is not None

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

    at = time.time()
    extracted = 0
    context = self._runner._get_context(self._runner._target)
    q = context.store().query()
    for path,blob in q.file_enum(pat=pat, regex=True):
      target = os.path.join(root, *path.split('/'))
      if extracted % 10000 == 0:
        ui.info(' .. {nr} files'.format(nr=extracted))
      os.makedirs(os.path.dirname(target), exist_ok=True)
      with open(target, 'wb') as f:
        f.write(blob)
        extracted += 1
    ui.success('done: {nr} files ({t:.02f} sec.)'.format(nr=extracted, t=(time.time() - at)))
