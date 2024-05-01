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
      '/f':dict(e=self._search_file, n='/f [pat]', d='search files those names matching pattern'),
      '/s':dict(e=self._search_string, n='/s pat [filepat]', d='search files for string'),
    }

  async def _search_file(self, args: deque[str]) -> None:
    self._helper.require_target()

    _ = args.popleft()

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    context = await self._helper.get_context().analyze(level=1)
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

    if args:
      mask = args.popleft()
    else:
      mask = None

    ui.info('searching: {pat}{mask}'.format(pat=pat, mask=' [file mask: {}]'.format(mask) if mask else ''))

    context = await self._helper.get_context().analyze(level=1)
    level = context.get_analysis_level()
    if level < 3:
      ui.warn('detected analysis level: {} ({}) -- try analyzing fully (\'aa\') to maximize coverage'.format(level, self._helper.decode_analysis_level(level)))
    for path, blob in context.store().query().file_enum(mask):
      if self._looks_binary(blob):
        for m0 in re.finditer(pat.encode('latin1'), blob):
          ui.info('{}:+{:08x}: {!r}'.format(path, m0.start(), m0.group(0)))
      else:
        from io import BytesIO
        for nr, t in enumerate(l.rstrip() for l in BytesIO(blob)):
          m = re.search(pat.encode('utf-8'), t)
          if m:
            ui.info('{}:{:d}:{:d}: {}'.format(path, nr+1, m.start(), t.decode('utf-8', 'replace')))

  def _looks_binary(self, b: bytes) -> bool:
    return b'\x00' in b
