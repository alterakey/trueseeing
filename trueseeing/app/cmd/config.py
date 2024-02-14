from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Dict
  from trueseeing.api import CommandHelper, Command, CommandMap, ConfigEntry

class ConfigCommand(CommandMixin):
  _confbag: Dict[str, ConfigEntry]

  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper
    self._confbag = self._helper._confbag  # type:ignore[attr-defined]

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return ConfigCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      '?e?':dict(e=self._help, n='?e?', d='config help'),
      'e':dict(e=self._manip, n='e key[=value]', d='get/set config'),
    }

  async def _help(self, args: deque[str]) -> None:
    ui.success('Configs:')
    if self._confbag:
      width = (2 + max([len(e.get('d', '')) for e in self._confbag.values()]) // 4) * 4
      for k in sorted(self._confbag):
        e = self._confbag[k]
        if 'n' in e:
          ui.stderr(
            f'{{n:<{width}s}}{{d}}'.format(n=e['n'], d=e['d'])
          )

  async def _manip(self, args: deque[str]) -> None:
    from trueseeing.core.exc import InvalidConfigKeyError
    _ = args.popleft()
    if not args:
      ui.fatal('need a config key')
    key = args.popleft()
    if args:
      if '=' != args.popleft():
        ui.fatal('got an unexpected token (try e key=value to set)')
      if not args:
        ui.fatal('need a value')
      value = args.popleft()

      try:
        self._helper.set_config(key, value)
      except InvalidConfigKeyError:
        ui.fatal(f'unknown key: {key}')
    else:
      try:
        ui.info('{}: {}'.format(key, self._helper.get_config(key)))
      except InvalidConfigKeyError:
        ui.fatal(f'unknown key: {key}')
