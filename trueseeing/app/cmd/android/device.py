from __future__ import annotations
from typing import TYPE_CHECKING

import re
from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui
from trueseeing.core.android.device import AndroidDevice

if TYPE_CHECKING:
  from typing import Optional
  from trueseeing.api import CommandHelper, Command, CommandMap
  from trueseeing.core.android.context import APKContext

class DeviceCommand(CommandMixin):
  _target_only: bool
  _watch_logcat: Optional[bytes]
  _watch_intent: Optional[bytes]

  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper
    self._target_pid = None
    self._target_only = False
    self._watch_logcat = None
    self._watch_intent = None

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return DeviceCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'dl':dict(e=self._device_watch_logcat, n='dl[!] [pat]', d='device: watch logcat (!: system-wide)'),
      'dl!':dict(e=self._device_watch_logcat),
      'di':dict(e=self._device_watch_intent, n='di[!] [pat]', d='device: watch intent'),
      'dx':dict(e=self._device_start, n='dx', d='device: start watching'),
      'xi':dict(e=self._exploit_dump_ui, n='xi [output.xml]', d='device: dump device UI'),
    }

  def _get_apk_context(self) -> APKContext:
    return self._helper.get_context().require_type('apk')

  async def _device_watch_logcat(self, args: deque[str]) -> None:
    cmd = args.popleft()

    if cmd.endswith('!'):
      self._target_only = False
    else:
      self._target_only = True
      _ = self._helper.require_target()

    if not args:
      self._watch_logcat = None
    else:
      pat = args.popleft()
      self._watch_logcat = pat.encode('latin1')

    if self._watch_logcat:
      ui.success('logcat watch enabled: {}'.format(self._watch_logcat.decode('latin1')))
    else:
      ui.success('logcat watch disabled')

  async def _device_watch_intent(self, args: deque[str]) -> None:
    _ = args.popleft()

    if not args:
      self._watch_intent = None
    else:
      pat = args.popleft()
      self._watch_intent = pat.encode('latin1')

    if self._watch_intent:
      ui.success('intent watch enabled: {}'.format(self._watch_intent.decode('latin1')))
    else:
      ui.success('intent watch disabled')

  async def _device_start(self, args: deque[str]) -> None:
    if not (self._watch_logcat or self._watch_intent):
      ui.fatal('nothing to watch (try di or dl beforehand)')

    pid: Optional[int] = None
    dev = AndroidDevice()
    ctx = self._get_apk_context()
    pkg = ctx.get_package_name()

    if self._target_only:
      await ctx.analyze(level=1)
      d = await dev.invoke_adb('shell ps')
      m = re.search(r'^[0-9a-zA-Z_]+ +([0-9]+) .*{}$'.format(pkg).encode(), d.encode(), re.MULTILINE)
      if m:
        pid = int(m.group(1))
        ui.info(f'detected target at pid: {pid}')

    try:
      ui.info('watching device (C-c to stop)')
      async for l in dev.invoke_adb_streaming('logcat -T1'):
        l = l.rstrip()
        if self._watch_logcat:
          if self._target_only:
            if not pid:
              m = re.search(r' ([0-9]+):{}'.format(pkg).encode(), l)
              if not m:
                continue
              pid = int(m.group(1))
              ui.info(f'detected target at pid: {pid}')
            else:
              m = re.search(r'\.[0-9]+? +{} +'.format(pid).encode(), l)
              if not m:
                continue
          if re.search(self._watch_logcat, l):
            ui.info('log: {}'.format(l.decode('latin1')))

        if self._watch_intent and b'intent' in l:
          if re.search(self._watch_intent, l):
            ui.info('intent: {}'.format(l.decode('latin1')))
    except KeyboardInterrupt:
      pass

  async def _exploit_dump_ui(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    ui.info('dumping UI hierachy')

    dev = AndroidDevice()
    msg = await dev.invoke_adb('shell uiautomator dump')
    m = re.search(r'dumped to: (/.*)', msg)
    if not m:
      ui.fatal(f'dump failed: {msg}')
    tmpfn = m.group(1)
    dom = await dev.invoke_adb(f'shell "cat {tmpfn}; rm {tmpfn}"')
    if outfn is None:
      ui.stdout(dom)
    else:
      with open(outfn, 'w') as f:
        f.write(dom)
    ui.success('done')
