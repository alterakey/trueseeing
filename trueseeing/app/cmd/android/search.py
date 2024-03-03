from __future__ import annotations
from typing import TYPE_CHECKING

import re
from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Optional, Iterator, Iterable, Tuple
  from trueseeing.api import CommandHelper, Command, CommandMap
  from trueseeing.core.android.model.code import Op
  from trueseeing.core.android.db import APKQuery

class SearchCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return SearchCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      '/c':dict(e=self._search_call, n='/c [pat]', d='search call for pattern'),
      '/k':dict(e=self._search_const, n='/k insn [pat]', d='search consts for pattern'),
      '/p':dict(e=self._search_put, n='/p[i] [pat]', d='search s/iputs for pattern'),
      '/dp':dict(e=self._search_defined_package, n='/dp [pat]', d='search packages matching pattern'),
      '/dc':dict(e=self._search_defined_class, n='/dc [pat]', d='search classes defined in packages matching pattern'),
      '/dcx':dict(e=self._search_derived_class, n='/dcx classpat [methpat]', d='search classes defining methods and extending ones matching patterns'),
      '/dci':dict(e=self._search_implementing_class, n='/dci ifacepat [methpat]', d='search classes defining methods and implementing interfaces matching patterns'),
      '/dm':dict(e=self._search_defined_method, n='/dm pat', d='search classes defining methods matching pattern'),
    }

  def _output_as_tagged_listing(self, is_header: bool, line: str) -> None:
    if is_header:
      ui.info(ui.colored(line, color='green'))
    else:
      ui.info(line)

  def _output_as_untagged_listing(self, is_header: bool, line: str) -> None:
    if not is_header:
      ui.info(line)

  async def _search_call(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need pattern')

    pat = args.popleft()

    from trueseeing.core.android.model.code import InvocationPattern
    context = await self._helper.get_context().require_type('apk').analyze()

    ui.info(f'searching call: {pat}')

    with context.store().query().scoped() as q:
      for is_header, line in OpFormatter(q).format(q.invocations(InvocationPattern('invoke-', pat))):
        self._output_as_tagged_listing(is_header, line)

  async def _search_const(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need insn')

    insn = args.popleft()
    if args:
      pat = args.popleft()
    else:
      pat = '.'

    from trueseeing.core.android.model.code import InvocationPattern
    context = await self._helper.get_context().require_type('apk').analyze()

    ui.info(f'searching const: {pat} [{insn}]')

    with context.store().query().scoped() as q:
      for is_header, line in OpFormatter(q).format(q.consts(InvocationPattern(insn, pat))):
        self._output_as_tagged_listing(is_header, line)

  async def _search_put(self, args: deque[str]) -> None:
    self._helper.require_target()

    cmd = args.popleft()

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    context = await self._helper.get_context().require_type('apk').analyze()
    q = context.store().query()
    if not cmd.endswith('i'):
      fun = q.sputs
      funtype = 's'
    else:
      fun = q.iputs
      funtype = 'i'

    ui.info(f'searching {funtype}puts: {pat}')

    for is_header, line in OpFormatter(q).format(fun(pat)):
      self._output_as_tagged_listing(is_header, line)

  async def _search_defined_package(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    import os
    context = await self._helper.get_context().require_type('apk').analyze()

    ui.info(f'searching packages defining class: {pat}')

    packages = set()
    for fn in (context.source_name_of_disassembled_class(r) for r in context.disassembled_classes()):
      if fn.endswith('.smali'):
        packages.add(os.path.dirname(fn))
    for pkg in sorted(packages):
      if re.match(pat, pkg):
        ui.info(pkg)

  async def _search_defined_class(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need pattern')

    pat = args.popleft()

    context = await self._helper.get_context().require_type('apk').analyze()

    ui.info(f'searching classes in package: {pat}')

    with context.store().query().scoped() as q:
      for is_header, line in OpFormatter(q).format(q.classes_in_package_named(pat)):
        self._output_as_untagged_listing(is_header, line)

  async def _search_derived_class(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need class')

    base = args.popleft()
    if args:
      pat = args.popleft()
    else:
      pat = '.'

    context = await self._helper.get_context().require_type('apk').analyze()

    if pat == '.':
      ui.info(f'searching classes deriving from: {base}')
    else:
      ui.info(f'searching classes deriving from: {base} [has method:{pat}]')

    with context.store().query().scoped() as q:
      for is_header, line in OpFormatter(q).format(q.classes_extends_has_method_named(pat, base)):
        self._output_as_untagged_listing(is_header, line)

  async def _search_implementing_class(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need pattern')

    interface = args.popleft()
    if args:
      pat = args.popleft()
    else:
      pat = '.'

    if pat == '.':
      ui.info(f'searching classes implementing: {interface}')
    else:
      ui.info(f'searching classes implementing: {interface} [has method:{pat}]')

    context = await self._helper.get_context().require_type('apk').analyze()
    q = context.store().query()
    for is_header, line in OpFormatter(q).format(q.classes_implements_has_method_named(pat, interface)):
      self._output_as_untagged_listing(is_header, line)

  async def _search_defined_method(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need classname')

    pat = args.popleft()

    ui.info(f'searching classes defining method: {pat}')

    context = await self._helper.get_context().require_type('apk').analyze()
    q = context.store().query()
    for is_header, line in OpFormatter(q).format(q.classes_has_method_named(pat)):
      self._output_as_untagged_listing(is_header, line)

class OpFormatter:
  def __init__(self, q: APKQuery, indent: int = 4) -> None:
    self._q = q
    self._indent = indent

  def format(self, ops: Iterable[Op]) -> Iterator[Tuple[bool, str]]:
    focus: Optional[str] = None
    for op in ops:
      qn = self._q.qualname_of(op)
      if qn is None:
        qn = self._q.class_name_of(op)
      if qn != focus:
        yield True, f'{qn}:'
        focus = qn
      yield False, '{ind}{op}'.format(
        ind=' '*self._indent,
        op='{id:08x}{sep}{d}'.format(sep=' '*4, id=(op._id if op._id else 0xfffffff), d=self._op(op))
      )

  def _op(self, o: Op) -> str:
    if o.t == 'directive':
      return self._op_directive(o)
    else:
      if o.v.startswith('invoke'):
        return self._op_invoke(o)
      elif o.v.startswith('const-string'):
        return self._op_const_str(o)
      else:
        return self._op_other(o)

  def _op_invoke(self, o: Op) -> str:
    regs = []
    trailers = []
    state = 0
    for t in o.p:
      if state == 0:
        if t.t in ['reg', 'multireg']:
          regs.append(t)
        else:
          state = 1
      if state == 1:
        if t.v == '{},': # XXX
          continue
        trailers.append(t)
    return '{insn} {{{regs}}}, {trailers}'.format(
      insn=o.v,
      regs=', '.join([self._p(x) for x in regs]),
      trailers=', '.join([self._p(x) for x in trailers]),
    )

  def _op_const_str(self, o: Op) -> str:
    reg = o.p[0]
    cons = o.p[1]
    return '{insn} {reg}, "{cons}"'.format(
      insn=o.v,
      reg=self._p(reg),
      cons=self._p(cons),
    )

  def _op_other(self, o: Op) -> str:
    return '{insn} {ps}'.format(
      insn=o.v,
      ps=', '.join([self._p(x) for x in o.p]),
    )

  def _op_directive(self, o: Op) -> str:
    return '.{insn} {ps}'.format(
      insn=o.v,
      ps=' '.join([self._p(x) for x in o.p]),
    )

  def _p(self, x: Op) -> str:
    return '{}' if x.v == '{},' else x.v
