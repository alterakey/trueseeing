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
      'i':dict(e=self._info, n='i[i]', d='print info (ii: more info)'),
      'ii':dict(e=self._info2),
    }

  def _read_field(self, x: Any) -> Any:
    boolmap = {True:'yes',False:'no','true':'yes','false':'no',1:'yes',0:'no', None:'?'}
    return boolmap.get(x, x)

  async def _info(self, args: deque[str], extended: bool = False) -> None:
    target = self._helper.require_target()

    _ = args.popleft()

    analysisguidemap = {
      0: 'try a;i for more info',
      1: 'try a;i for more info',
      2: 'try aa;i for more info',
      3: 'try aaa;i for more info',
    }

    context = self._helper.get_context()
    analyzed = context.get_analysis_level()

    ui.info(f'info on {target}')

    async for m in context._get_info(extended):
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
    return await self._info(args, extended=True)
