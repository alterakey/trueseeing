from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Any
  from trueseeing.api import CommandHelper, Command, CommandMap

class InfoCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return InfoCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'i':dict(e=self._info, n='i[i][i]', d='print info (ii: overall, iii: detailed)'),
      'ii':dict(e=self._info2),
      'iii':dict(e=self._info3),
    }

  def _read_field(self, x: Any) -> Any:
    boolmap = {True:'yes',False:'no','true':'yes','false':'no',1:'yes',0:'no', None:'?'}
    return boolmap.get(x, x)

  async def _info(self, args: deque[str], level: int = 0) -> None:
    target = self._helper.require_target()

    _ = args.popleft()

    analysisguidemap = {
      0: 'try ii for more info',
      1: 'try iii for more info',
      2: 'try iii for more info',
      3: 'try aaa;i for more info',
    }

    context = self._helper.get_context()
    analyzed = context.get_analysis_level()
    if analyzed < level:
      await context.analyze(level=level)
      analyzed = level

    ui.info(f'info on {target}')

    async for m in context._get_info():
      for k, v in m.items():
        if v is None:
          continue
        if not k.startswith('_'):
          ui.info('{:12s} {}'.format(k, self._read_field(v)))
        elif k == '_patch':
          ui.info('{:12s} {}'.format('has patch?', self._read_field(v)))
        elif k == '_analysis':
          ui.info('{:12s} {}{}'.format(
            'analyzed?',
            self._helper.decode_analysis_level(analyzed),
            ' ({})'.format(analysisguidemap[analyzed]) if analyzed < 4 else '',
          ))

  async def _info2(self, args: deque[str]) -> None:
    return await self._info(args, level=1)

  async def _info3(self, args: deque[str]) -> None:
    return await self._info(args, level=3)
