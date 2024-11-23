from __future__ import annotations
from typing import TYPE_CHECKING, NamedTuple

import re
from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui, OpFormatter, OpLister

if TYPE_CHECKING:
  from typing import Optional
  from trueseeing.api import CommandHelper, Command, CommandMap
  from trueseeing.core.android.context import APKContext

class QualNameInfo(NamedTuple):
  clazz: str
  method: Optional[str]

class ShowCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return ShowCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'pd':dict(e=self._show_disasm, n='pd qualname', d='show disassembled class/method', t={'apk'}),
      'pk':dict(e=self._show_solved_constant, n='pk[!] 0xaddr index', d='guess and show what constant would flow into the index-th arg of op (!: try harder)', t={'apk'}),
      'pk!':dict(e=self._show_solved_constant, t={'apk'}),
      'pt':dict(e=self._show_solved_typeset, n='pt 0xaddr index', d='guess and show what type would flow into the index-th arg of op', t={'apk'}),
    }

  async def _show_disasm(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    try:
      qn = args.popleft()
    except IndexError:
      ui.fatal('need a qualname')

    context: APKContext = self._helper.get_context().require_type('apk')
    await context.analyze()

    try:
      c = self._parse_qualname(qn)
    except ValueError:
      ui.fatal(f'invalid qualname (try quoting): {qn}')

    with context.store().query().scoped() as q:
      OpLister(OpFormatter(q)).list_tagged(q.body(c.clazz, c.method))

  def _parse_qualname(self, n: str) -> QualNameInfo:
    m = re.fullmatch('(L[^ ]+?;)(->[^ ]+?)?', n)
    if m is None:
      raise ValueError('invalid dalvik name: {n}') # XXX
    return QualNameInfo(
      clazz=m.group(1),
      method=m.group(2)[2:] if m.group(2) else None,
    )

  async def _show_solved_constant(self, args: deque[str]) -> None:
    self._helper.require_target()

    cmd = args.popleft()

    if len(args) < 2:
      ui.fatal('need addr and index')

    addr = int(args.popleft(), 16)
    idx = int(args.popleft())

    limit = self._helper.get_graph_size_limit(self._helper.get_modifiers(args))

    from trueseeing.core.android.analyze.flow import DataFlow
    with DataFlow.apply_max_graph_size(limit):
      context = await self._helper.get_context().require_type('apk').analyze()
      store = context.store()
      q = store.query()
      op = q.op_get(addr)
      if op is not None:
        if cmd.endswith('!'):
          vs = DataFlow(q).solved_possible_constant_data_in_invocation(op, idx)
          ui.info(repr(vs))
        else:
          try:
            v = DataFlow(q).solved_constant_data_in_invocation(op, idx)
            ui.info(repr(v))
          except DataFlow.UnsolvableValueError as ce:
            if not ui.is_debugging:
              ui.error('value is not solvable (possibly not a compile-time constant); try enabling debug mode (e core.debug=true) to see the data graph')
            else:
              ui.error(f'value is not solvable (possibly not a compile-time constant), data graph: {ce.graph}')
          except DataFlow.NoSuchValueError as e:
            ui.error(str(e))
      else:
        ui.error('0x{:08x}: invalid address'.format(addr))

  async def _show_solved_typeset(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if len(args) < 2:
      ui.fatal('need addr and index')

    addr = int(args.popleft(), 16)
    idx = int(args.popleft())

    limit = self._helper.get_graph_size_limit(self._helper.get_modifiers(args))

    from trueseeing.core.android.analyze.flow import DataFlow
    with DataFlow.apply_max_graph_size(limit):
      context = await self._helper.get_context().require_type('apk').analyze()
      store = context.store()
      q = store.query()
      op = q.op_get(addr)
      if op is not None:
        vs = DataFlow(q).solved_typeset_in_invocation(op, idx)
        ui.info(repr(vs))
      else:
        ui.error('0x{:08x}: invalid address'.format(addr))
