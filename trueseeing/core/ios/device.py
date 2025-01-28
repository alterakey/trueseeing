from __future__ import annotations
from typing import TYPE_CHECKING

from functools import cache
from trueseeing.core.env import get_adb_host
from trueseeing.core.tools import invoke, invoke_passthru, invoke_streaming
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Optional, AsyncIterator, Any

class IOSDevice:
  def __init__(self) -> None:
    pass

  async def invoke_frida(self, cmd: str, **kwargs: Any) -> str:
    self._require_frida()
    line = self._get_frida_cmdline(cmd)
    ui.debug("invoking: {line}")
    return await invoke(line, **kwargs)

  async def invoke_frida_passthru(self, cmd: str, **kwargs: Any) -> None:
    self._require_frida()
    line = self._get_frida_cmdline(cmd)
    ui.debug("invoking: {line}")
    await invoke_passthru(line, **kwargs)

  async def invoke_frida_streaming(self, cmd: str, **kwargs: Any) -> AsyncIterator[bytes]:
    self._require_frida()
    line = self._get_frida_cmdline(cmd)
    ui.debug("invoking: {line}")
    async for l in invoke_streaming(line, **kwargs):
      yield l

  def get_frida_cmdline(self, cmd: str) -> str:
    return self._get_frida_cmdline(cmd)

  def _get_frida_cmdline(self, cmd: str) -> str:
    host: Optional[str] = get_adb_host()

    line = 'env USBMUXD_SOCKET_ADDRESS={host} {cmd}'.format(
      host=host if host else '',
      cmd=cmd
    )
    return line

  def require_frida(self) -> None:
    return self._require_frida()

  @cache
  def _require_frida(self) -> None:
    from trueseeing.core.tools import require_in_path
    require_in_path('frida', 'frida --version')
