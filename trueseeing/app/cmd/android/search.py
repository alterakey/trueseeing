from __future__ import annotations
from typing import TYPE_CHECKING

import re
from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui, OpFormatter, OpLister

if TYPE_CHECKING:
  from trueseeing.api import CommandHelper, Command, CommandMap

class SearchCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return SearchCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      '/c':dict(e=self._search_call, n='/c [pat]', d='search call for pattern', t={'apk'}),
      '/k':dict(e=self._search_const, n='/k insn [pat]', d='search consts for pattern', t={'apk'}),
      '/p':dict(e=self._search_put, n='/p[i] [pat]', d='search s/iputs for pattern', t={'apk'}),
      '/dp':dict(e=self._search_defined_package, n='/dp [pat]', d='search packages matching pattern', t={'apk'}),
      '/dc':dict(e=self._search_defined_class, n='/dc [pat]', d='search classes matching pattern', t={'apk'}),
      '/dcx':dict(e=self._search_derived_class, n='/dcx classpat [methpat]', d='search classes defining methods and extending ones matching patterns', t={'apk'}),
      '/dci':dict(e=self._search_implementing_class, n='/dci ifacepat [methpat]', d='search classes defining methods and implementing interfaces matching patterns', t={'apk'}),
      '/dm':dict(e=self._search_defined_method, n='/dm pat', d='search classes defining methods matching pattern', t={'apk'}),
    }

  async def _search_call(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need pattern')

    pat = args.popleft()

    from trueseeing.core.android.model import InvocationPattern
    context = await self._helper.get_context().require_type('apk').analyze()

    ui.info(f'searching call: {pat}')

    with context.store().query().scoped() as q:
      OpLister(OpFormatter(q)).list_tagged(q.invocations(InvocationPattern('invoke-', pat)))

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

    from trueseeing.core.android.model import InvocationPattern
    context = await self._helper.get_context().require_type('apk').analyze()

    ui.info(f'searching const: {pat} [{insn}]')

    with context.store().query().scoped() as q:
      OpLister(OpFormatter(q)).list_tagged(q.consts(InvocationPattern(insn, pat)))

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

    OpLister(OpFormatter(q)).list_tagged(fun(pat))

  async def _search_defined_package(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    import os
    context = await self._helper.get_context().require_type('apk').analyze()

    ui.info(f'searching packages: {pat}')

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

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    context = await self._helper.get_context().require_type('apk').analyze()

    ui.info(f'searching classes: {pat}')

    with context.store().query().scoped() as q:
      for name in q.class_names(pat):
        ui.info(name)

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
      OpLister(OpFormatter(q)).list_untagged(q.classes_extends_has_method_named(pat, base))

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
    OpLister(OpFormatter(q)).list_untagged(q.classes_implements_has_method_named(pat, interface))

  async def _search_defined_method(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need classname')

    pat = args.popleft()

    ui.info(f'searching classes defining method: {pat}')

    context = await self._helper.get_context().require_type('apk').analyze()
    q = context.store().query()
    OpLister(OpFormatter(q)).list_untagged(q.classes_has_method_named(pat))
