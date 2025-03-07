from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Literal
  from trueseeing.api import CommandHelper, Command, CommandMap

  UIPatternType = Literal['re', 'xpath']

class ReconCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return ReconCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'rp':dict(e=self._recon_list_packages, n='rp', d='recon: list installed packages', t={'ipa'}),
    }

  async def _recon_list_packages(self, args: deque[str]) -> None:
    _ = args.popleft()

    ui.info('listing packages')

    import time
    import re
    import io
    from trueseeing.core.ios.device import IOSDevice

    dev = IOSDevice()

    at = time.time()
    nr = 0
    for l in io.StringIO(await dev.invoke_frida('frida-ps @dev@ -ai')):
      if l.startswith('----'):
        continue
      m = re.match(r'^\s*([0-9-]+)\s+(.*?)\s+([a-z0-9._-]+)\s*$', l)
      if not m:
        continue
      if m.group(1) == '-':
        ui.info('{bid} ({name})'.format(bid=m.group(3), name=m.group(2)))
      else:
        ui.info('{bid} ({name}) [{pid}]'.format(bid=m.group(3), name=m.group(2), pid=m.group(1)))
      nr += 1
    ui.success('done, {nr} packages found ({t:.02f} sec.)'.format(nr=nr, t=(time.time() - at)))
