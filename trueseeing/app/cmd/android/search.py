from __future__ import annotations
from typing import TYPE_CHECKING

import re
from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

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
      '/c':dict(e=self._search_call, n='/c [pat]', d='search call for pattern'),
      '/k':dict(e=self._search_const, n='/k insn [pat]', d='search consts for pattern'),
      '/p':dict(e=self._search_put, n='/p[i] [pat]', d='search s/iputs for pattern'),
      '/dp':dict(e=self._search_defined_package, n='/dp [pat]', d='search packages matching pattern'),
      '/dc':dict(e=self._search_defined_class, n='/dc [pat]', d='search classes defined in packages matching pattern'),
      '/dcx':dict(e=self._search_derived_class, n='/dcx class [pat]', d='search classes extending ones matching pattern'),
      '/dci':dict(e=self._search_implementing_class, n='/dci interface [pat]', d='search classes implementing interfaces matching pattern'),
      '/dm':dict(e=self._search_defined_method, n='/dm class [pat]', d='search classes defining methods matching pattern'),
      '/f':dict(e=self._search_file, n='/f [pat]', d='search files those names matching pattern'),
      '/s':dict(e=self._search_string, n='/s pat', d='search files for string'),
    }

  async def _search_file(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    context = await self._helper.get_context_analyzed('apk', level=1)
    level = context.get_analysis_level()
    if level < 3:
      ui.warn('detected analysis level: {} ({}) -- try analyzing fully (\'aa\') to maximize coverage'.format(level, self._helper.decode_analysis_level(level)))
    for path in context.store().query().file_find(pat=pat, regex=True):
      ui.info(f'{path}')

  async def _search_string(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need pattern')

    pat = args.popleft()

    ui.info('searching in files: {pat}'.format(pat=pat))

    context = await self._helper.get_context_analyzed('apk', level=1)
    level = context.get_analysis_level()
    if level < 3:
      ui.warn('detected analysis level: {} ({}) -- try analyzing fully (\'aa\') to maximize coverage'.format(level, self._helper.decode_analysis_level(level)))
    for path in context.store().query().file_search(pat=pat.encode('latin1'), regex=True):
      ui.info(f'{path}')

  async def _search_call(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need pattern')

    pat = args.popleft()

    from trueseeing.core.android.model.code import InvocationPattern
    context = await self._helper.get_context_analyzed('apk')
    q = context.store().query()
    for op in q.invocations(InvocationPattern('invoke-', pat)):
      qn = q.qualname_of(op)
      ui.info(f'{qn}: {op}')

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
    context = await self._helper.get_context_analyzed('apk')
    q = context.store().query()
    for op in q.consts(InvocationPattern(insn, pat)):
      qn = q.qualname_of(op)
      ui.info(f'{qn}: {op}')

  async def _search_put(self, args: deque[str]) -> None:
    self._helper.require_target()

    cmd = args.popleft()

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    context = await self._helper.get_context_analyzed('apk')
    q = context.store().query()
    if not cmd.endswith('i'):
      fun = q.sputs
    else:
      fun = q.iputs

    for op in fun(pat):
      qn = q.qualname_of(op)
      ui.info(f'{qn}: {op}')

  async def _search_defined_package(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    import os
    context = await self._helper.get_context_analyzed('apk')
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

    context = await self._helper.get_context_analyzed('apk')
    q = context.store().query()
    for op in q.classes_in_package_named(pat):
      cn = q.class_name_of(op)
      ui.info(f'{cn}: {op}')

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

    context = await self._helper.get_context_analyzed('apk')
    q = context.store().query()
    for op in q.classes_extends_has_method_named(base, pat):
      cn = q.class_name_of(op)
      ui.info(f'{cn}: {op}')

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

    context = await self._helper.get_context_analyzed('apk')
    q = context.store().query()
    for op in q.classes_implements_has_method_named(interface, pat):
      cn = q.class_name_of(op)
      ui.info(f'{cn}: {op}')

  async def _search_defined_method(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if not args:
      ui.fatal('need classname')

    pat = args.popleft()

    context = await self._helper.get_context_analyzed('apk')
    q = context.store().query()
    for op in q.classes_has_method_named(pat):
      qn = q.qualname_of(op)
      ui.info(f'{qn}: {op}')
