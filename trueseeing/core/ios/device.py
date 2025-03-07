from __future__ import annotations
from typing import TYPE_CHECKING

from functools import cache
from trueseeing.core.env import get_ios_frida_server_host
from trueseeing.core.tools import invoke, invoke_passthru, invoke_streaming
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import AsyncIterator, Any

class IOSDevice:
  _marker: str = '@dev@'

  async def invoke_frida(self, cmd: str, **kwargs: Any) -> str:
    self._require_frida()
    line = self._patch_frida_target_args(cmd)
    ui.debug(f"invoking: {line}")
    return await invoke(line, **kwargs)

  async def invoke_frida_passthru(self, cmd: str, **kwargs: Any) -> None:
    self._require_frida()
    line = self._patch_frida_target_args(cmd)
    ui.debug(f"invoking: {line}")
    await invoke_passthru(line, **kwargs)

  async def invoke_frida_streaming(self, cmd: str, **kwargs: Any) -> AsyncIterator[bytes]:
    self._require_frida()
    line = self._patch_frida_target_args(cmd)
    ui.debug(f"invoking: {line}")
    async for l in invoke_streaming(line, **kwargs):
      yield l

  def _patch_frida_target_args(self, cmd: str) -> str:
    return cmd.replace(
      self._marker,
      '-H {host}'.format(
        host=get_ios_frida_server_host()
      ))

  def require_frida(self) -> None:
    return self._require_frida()

  @cache
  def _require_frida(self) -> None:
    from trueseeing.core.tools import require_in_path
    require_in_path('frida', 'frida --version')
    require_in_path(
      'frida-ps',
      self._patch_frida_target_args('frida-ps @dev@'),
      msg='cannot connect to frida-server: {host} (try tunnelling there to device, 27042/tcp or wherever frida-server is running at)'.format(
        host=get_ios_frida_server_host()
      ))
