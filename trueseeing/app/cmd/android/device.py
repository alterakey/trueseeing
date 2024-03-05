from __future__ import annotations
from typing import TYPE_CHECKING

import re
from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui
from trueseeing.core.android.device import AndroidDevice

if TYPE_CHECKING:
  from typing import Optional, Tuple, Literal, AsyncIterator
  from trueseeing.api import CommandHelper, Command, CommandMap
  from trueseeing.core.android.context import APKContext

  UIPatternType = Literal['re', 'xpath']

class DeviceCommand(CommandMixin):
  _target_only: bool
  _watch_logcat: Optional[bytes]
  _watch_intent: Optional[bytes]
  _watch_ui: Optional[Tuple[str, UIPatternType]]
  _watch_ui_outfn: Optional[str]

  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper
    self._target_pid = None
    self._target_only = False
    self._watch_logcat = None
    self._watch_intent = None
    self._watch_ui = None
    self._watch_ui_outfn = None

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return DeviceCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'dl':dict(e=self._device_watch_logcat, n='dl[!] [pat]', d='device: watch logcat (!: system-wide)'),
      'dl!':dict(e=self._device_watch_logcat),
      'dt':dict(e=self._device_watch_intent, n='dt[!] [pat]', d='device: watch intent'),
      'di':dict(e=self._device_watch_ui, n='di[!] [pat|xp:xpath] [output.xml]', d='device: watch device UI'),
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

  async def _device_watch_ui(self, args: deque[str]) -> None:
    cmd = args.popleft()

    if not args:
      self._watch_ui = None
    else:
      pat = args.popleft()
      if pat.startswith('xp:'):
        self._watch_ui = pat[3:], 'xpath'
      else:
        self._watch_ui = pat, 're'

      if args:
        import os
        outfn = args.popleft()
        if os.path.exists(outfn) and not cmd.endswith('!'):
          ui.fatal('outfile exists; force (!) to overwrite')
        self._outfn_ui = outfn

    if self._watch_ui:
      ui.success('ui watch enabled: {} [{}]'.format(self._watch_ui[0], self._watch_ui[1]))
    else:
      ui.success('ui watch disabled')

  async def _device_start(self, args: deque[str]) -> None:
    if not (self._watch_logcat or self._watch_intent or self._watch_ui):
      ui.fatal('nothing to watch (try di/dl/dt beforehand)')

    dev = AndroidDevice()
    ctx = self._get_apk_context()
    pkg = ctx.get_package_name()

    if self._target_only:
      await ctx.analyze(level=1)

    async def _log() -> None:
      pid: Optional[int] = None
      if self._target_only:
        d = await dev.invoke_adb('shell ps')
        m = re.search(r'^[0-9a-zA-Z_]+ +([0-9]+) .*{}$'.format(pkg).encode(), d.encode(), re.MULTILINE)
        if m:
          pid = int(m.group(1))
          ui.info(f'detected target at pid: {pid}')

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

    async def _ui() -> None:
      import lxml.etree as ET
      import re

      if self._watch_ui:
        pat, typ = self._watch_ui

        async for dom in self._dump_ui_cont():
          matched = False
          if typ == 'xpath':
            r = ET.fromstring(dom)
            e = r.xpath(pat)
            if e:
              matched = True
              ui.info('ui: {} [{}]: found {}{}'.format(pat, typ, len(e), ' (dumped)' if self._watch_ui_outfn else ''))
          else:
            m = re.search(pat, dom)
            if m:
              matched = True
              ui.info('ui: {} [{}]: found {}'.format(pat, typ, ' (dumped)' if self._watch_ui_outfn else ''))

          if matched:
            if self._watch_ui_outfn:
              with open(self._watch_ui_outfn, 'w') as f:
                f.write(dom)

    try:
      from asyncio import gather
      ui.info('watching device (C-c to stop)')
      await gather(_log(), _ui(), return_exceptions=True)
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

    try:
      dom = await self._dump_ui()
    except DumpFailedError as e:
      ui.fatal(f'dump failed: {e}')

    if outfn is None:
      ui.stdout(dom)
    else:
      with open(outfn, 'w') as f:
        f.write(dom)
    ui.success('done')

  async def _dump_ui(self) -> str:
    from subprocess import CalledProcessError
    dev = AndroidDevice()
    try:
      msg = await dev.invoke_adb('shell uiautomator dump')
      m = re.search(r'dumped to: (/.*)', msg)
      if not m:
        raise DumpFailedError(msg)
      tmpfn = m.group(1)
      return await dev.invoke_adb(f'shell "cat {tmpfn}; rm {tmpfn}"')
    except CalledProcessError as e:
      raise DumpFailedError(e)

  async def _dump_ui_cont(self, /, delay: float = 1.0) -> AsyncIterator[str]:
    from subprocess import CalledProcessError
    dev = AndroidDevice()
    try:
      async for msg in dev.invoke_adb_streaming(r'shell "while (true) do uiautomator dump /sdcard/dump-\$(date +%s).xml; sleep {delay}; done"'.format(delay=delay)):
        m = re.search(r'dumped to: (/.*)', msg.decode())
        if m:
          tmpfn = m.group(1)
          yield await dev.invoke_adb(f'shell "cat {tmpfn}; rm {tmpfn}"')
    except CalledProcessError as e:
      raise DumpFailedError(e)


class DumpFailedError(Exception):
  pass
