from __future__ import annotations
from typing import TYPE_CHECKING

import sys
from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Optional
  from trueseeing.api import CommandHelper, Command, CommandMap

class ShowCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return ShowCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'pf':dict(e=self._show_file, n='pf[x][!] path [output.bin]', d='show file (x: hex)'),
      'pf!':dict(e=self._show_file),
      'pfx':dict(e=self._show_file),
      'pfx!':dict(e=self._show_file),
    }

  async def _show_file(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._helper.require_target()

    cmd = args.popleft()

    if not args:
      ui.fatal('need path')

    path = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from binascii import hexlify

    context = await self._helper.get_context().analyze(level=1)
    level = context.get_analysis_level()
    if level < 3:
      ui.warn('detected analysis level: {} ({}) -- try analyzing fully (\'aa\') to maximize coverage'.format(level, self._helper.decode_analysis_level(level)))
    d = context.store().query().file_get(path)
    if d is None:
      ui.fatal('file not found')
    if outfn is None:
      sys.stdout.buffer.write(d if 'x' not in cmd else hexlify(d))
    else:
      with open(outfn, 'wb') as f:
        f.write(d if 'x' not in cmd else hexlify(d))
