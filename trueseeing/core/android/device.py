from __future__ import annotations
from typing import TYPE_CHECKING

from functools import cache
from trueseeing.core.env import get_adb_host
from trueseeing.core.tools import invoke, invoke_passthru, invoke_streaming
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Optional, AsyncIterator, Any

class AndroidDevice:
  def __init__(self) -> None:
    pass

  async def invoke_adb(self, cmd: str, **kwargs: Any) -> str:
    self._require_adb()
    line = self._get_adb_cmdline(cmd)
    ui.debug("invoking: {line}")
    return await invoke(line, **kwargs)

  async def invoke_adb_passthru(self, cmd: str, **kwargs: Any) -> None:
    self._require_adb()
    line = self._get_adb_cmdline(cmd)
    ui.debug("invoking: {line}")
    await invoke_passthru(line, **kwargs)

  async def invoke_adb_streaming(self, cmd: str, **kwargs: Any) -> AsyncIterator[bytes]:
    self._require_adb()
    line = self._get_adb_cmdline(cmd)
    ui.debug("invoking: {line}")
    async for l in invoke_streaming(line, **kwargs):
      yield l

  def get_adb_cmdline(self, cmd: str) -> str:
    return self._get_adb_cmdline(cmd)

  def _get_adb_cmdline(self, cmd: str) -> str:
    host: Optional[str] = get_adb_host()

    line = 'adb {host} {cmd}'.format(
      host=f'-L {host}' if host else '',
      cmd=cmd
    )
    return line

  def require_adb(self) -> None:
    return self._require_adb()

  @cache
  def _require_adb(self) -> None:
    from trueseeing.core.tools import require_in_path
    require_in_path('adb', 'adb version')

  async def is_fullbackup_available(self) -> bool:
    out = await self.invoke_adb('backup 2>&1 || exit 0')
    return 'backup either' in out

  async def is_package_debuggable(self, package: str) -> bool:
    out = await self.invoke_adb(f"shell 'run-as {package} ls' 2>&1 || exit 0")
    return 'package not debuggable' not in out
