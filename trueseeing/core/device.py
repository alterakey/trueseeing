from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.core.env import get_adb_host
from trueseeing.core.tools import invoke, invoke_passthru
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Optional

class AndroidDevice:
  def __init__(self) -> None:
    pass

  async def invoke_adb(self, cmd: str) -> str:
    line = self._get_adb_cmdline(cmd)
    ui.debug("invoking: {line}")
    return await invoke(line)

  async def invoke_adb_passthru(self, cmd: str) -> None:
    line = self._get_adb_cmdline(cmd)
    ui.debug("invoking: {line}")
    await invoke_passthru(line)

  def _get_adb_cmdline(self, cmd: str) -> str:
    host: Optional[str] = get_adb_host()

    line = 'adb {host} {cmd}'.format(
      host=f'-L {host}' if host else '',
      cmd=cmd
    )
    return line
