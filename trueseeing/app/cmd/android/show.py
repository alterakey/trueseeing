from __future__ import annotations
from typing import TYPE_CHECKING

import re
import sys
from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Optional, TypedDict
  from trueseeing.api import CommandHelper, Command, CommandMap
  from trueseeing.core.android.context import APKContext

  class QualNameInfo(TypedDict):
    path: str
    sig: str

class ShowCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return ShowCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'pd':dict(e=self._show_disasm, n='pd[!] qualname [output.smali]', d='show disassembled class/method'),
      'pd!':dict(e=self._show_disasm),
      'pk':dict(e=self._show_solved_constant, n='pk 0xop index', d='guess and show what constant would flow into the index-th arg of op (!: try harder)'),
      'pt':dict(e=self._show_solved_typeset, n='pt 0xop index', d='guess and show what type would flow into the index-th arg of op'),
    }

  async def _show_disasm(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._helper.require_target()

    cmd = args.popleft()

    if not args:
      ui.fatal('need a qualname')

    qn = args.popleft()

    import os

    if args:
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    context: APKContext = self._helper.get_context().require_type('apk')

    try:
      c = self._parse_qualname(qn)
    except ValueError:
      ui.fatal(f'invalid qualname (try quoting): {qn}')

    with context.store().query().scoped() as q:
      for _, d in q.file_enum('smali%/{}'.format(c['path'])):
        if outfn is None:
          f = sys.stdout.buffer
        else:
          f = open(outfn, 'wb')
        try:
          if not c['sig']:
            f.write(d)
          else:
            from io import BytesIO
            pat = r'\.method.*? {}$'.format(re.escape(c['sig'])).encode('utf-8')
            state = 0
            for l in BytesIO(d):
              if state == 0:
                if re.match(pat, l):
                  f.write(l)
                  state = 1
              elif state == 1:
                f.write(l)
                if l == b'.end method\n':
                  state = 2
              elif state == 2:
                break
        finally:
          if f != sys.stdout.buffer:
            f.close()

  def _parse_qualname(self, n: str) -> QualNameInfo:
    m = re.fullmatch('(L[^ ]+?;)(->[^ ]+?)?', n)
    if m is None:
      raise ValueError('invalid dalvik name: {n}') # XXX
    return dict(
      path='{}.smali'.format(m.group(1)[1:-1]),
      sig=m.group(2)[2:] if m.group(2) else '',
    )

  async def _show_solved_constant(self, args: deque[str]) -> None:
    self._helper.require_target()

    cmd = args.popleft()

    if len(args) < 2:
      ui.fatal('need op and index')

    opn = int(args.popleft(), 16)
    idx = int(args.popleft())

    limit = self._helper.get_graph_size_limit(self._helper.get_modifiers(args))

    from trueseeing.core.android.analysis.flow import DataFlow
    with DataFlow.apply_max_graph_size(limit):
      context = await self._helper.get_context().require_type('apk').analyze()
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

    opn = int(args.popleft(), 16)
    idx = int(args.popleft())

    limit = self._helper.get_graph_size_limit(self._helper.get_modifiers(args))

    from trueseeing.core.android.analysis.flow import DataFlow
    with DataFlow.apply_max_graph_size(limit):
      context = await self._helper.get_context().require_type('apk').analyze()
      store = context.store()
      q = store.query()
      op = q.op_get(opn)
      if op is not None:
        vs = DataFlow(q).solved_typeset_in_invocation(op, idx)
        ui.info(repr(vs))
      else:
        ui.error('op #{} not found'.format(opn))
