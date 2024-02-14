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
      'pd':dict(e=self._show_disasm, n='pd[!] class [output.smali]', d='show disassembled class'),
      'pd!':dict(e=self._show_disasm),
      'pk':dict(e=self._show_solved_constant, n='pk op index', d='guess and show what constant would flow into the index-th arg of op (!: try harder)'),
      'pt':dict(e=self._show_solved_typeset, n='pt op index', d='guess and show what type would flow into the index-th arg of op'),
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

    context = await self._helper.get_context_analyzed('apk', level=1)
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

  async def _show_disasm(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._helper.require_target()

    cmd = args.popleft()

    if not args:
      ui.fatal('need class')

    class_ = args.popleft()

    import os

    if args:
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    context = await self._helper.get_context_analyzed('apk')
    path = '{}.smali'.format(os.path.join(*(class_.split('.'))))
    for _, d in context.store().query().file_enum(f'smali%/{path}'):
      if outfn is None:
        sys.stdout.buffer.write(d)
      else:
        with open(outfn, 'wb') as f:
          f.write(d)

  async def _show_solved_constant(self, args: deque[str]) -> None:
    self._helper.require_target()

    cmd = args.popleft()

    if len(args) < 2:
      ui.fatal('need op and index')

    opn = int(args.popleft())
    idx = int(args.popleft())

    limit = self._helper.get_graph_size_limit(self._helper.get_modifiers(args))

    from trueseeing.core.android.analysis.flow import DataFlow
    with DataFlow.apply_max_graph_size(limit):
      context = await self._helper.get_context_analyzed('apk')
      store = context.store()
      q = store.query()
      op = q.op_get(opn)
      if op is not None:
        if cmd.endswith('!'):
          vs = DataFlow(q).solved_possible_constant_data_in_invocation(op, idx)
          ui.info(repr(vs))
        else:
          try:
            v = DataFlow(q).solved_constant_data_in_invocation(op, idx)
            ui.info(repr(v))
          except DataFlow.NoSuchValueError as e:
            ui.error(str(e))
      else:
        ui.error('op #{} not found'.format(opn))

  async def _show_solved_typeset(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if len(args) < 2:
      ui.fatal('need op and index')

    opn = int(args.popleft())
    idx = int(args.popleft())

    limit = self._helper.get_graph_size_limit(self._helper.get_modifiers(args))

    from trueseeing.core.android.analysis.flow import DataFlow
    with DataFlow.apply_max_graph_size(limit):
      context = await self._helper.get_context_analyzed('apk')
      store = context.store()
      q = store.query()
      op = q.op_get(opn)
      if op is not None:
        vs = DataFlow(q).solved_typeset_in_invocation(op, idx)
        ui.info(repr(vs))
      else:
        ui.error('op #{} not found'.format(opn))
