from __future__ import annotations
from typing import TYPE_CHECKING

import re
from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui
from trueseeing.core.android.device import AndroidDevice

if TYPE_CHECKING:
  from typing import Optional, Tuple, Literal, AsyncIterator, List, Dict, Mapping, Iterator
  from trueseeing.api import CommandHelper, Command, CommandMap, OptionMap
  from trueseeing.core.android.context import APKContext

  UIPatternType = Literal['re', 'xpath']

class DeviceCommand(CommandMixin):
  _target_only: bool
  _watch_logcat: Optional[bytes]
  _watch_intent: Optional[bytes]
  _watch_fs: Optional[bytes]
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
    self._watch_fs = None

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return DeviceCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'dl':dict(e=self._device_watch_logcat, n='dl[!] [pat]', d='device: watch logcat (!: system-wide)'),
      'dl!':dict(e=self._device_watch_logcat),
      'df':dict(e=self._device_watch_fs, n='df', d='device: watch filesystem'),
      'dt':dict(e=self._device_watch_intent, n='dt[!] [pat]', d='device: watch intent'),
      'di':dict(e=self._device_watch_ui, n='di[!] [pat|xp:xpath] [output.xml]', d='device: watch device UI'),
      'dx':dict(e=self._device_start, n='dx', d='device: start watching'),
      'xi':dict(e=self._exploit_dump_ui, n='xi [output.xml]', d='device: dump device UI'),
      'xz':dict(e=self._exploit_fuzz_intent, n='xz[!] "am-cmdline-template" [output.txt]', d='device: fuzz intent'),
      'xz!':dict(e=self._exploit_fuzz_intent),
      'xzr':dict(e=self._exploit_fuzz_command, n='xzr[!] "cmdline-template" [output.txt]', d='device: fuzz cmdline'),
      'xzr!':dict(e=self._exploit_fuzz_command),
    }

  def get_options(self) -> OptionMap:
    return {
      'w':dict(n='wNAME=FN', d='wordlist, use as {NAME} [xz]'),
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

  async def _device_watch_fs(self, args: deque[str]) -> None:
    _ = args.popleft()

    if not args:
      self._watch_fs = None
    else:
      pat = args.popleft()
      self._watch_fs = pat.encode('latin1')

    if self._watch_fs:
      ui.success('filesystem watch enabled: {}'.format(self._watch_fs.decode('latin1')))
    else:
      ui.success('filesystem watch disabled')

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
    if not (self._watch_logcat or self._watch_intent or self._watch_ui or self._watch_fs):
      ui.fatal('nothing to watch (try d* beforehand)')

    dev = AndroidDevice()
    ctx = self._get_apk_context()
    pkg = ctx.get_package_name()

    if self._target_only:
      await ctx.analyze(level=1)

    async def _log() -> None:
      pid: Optional[int] = None
      if self._watch_logcat or self._watch_intent:
        if not pid:
          d = await dev.invoke_adb('shell ps')
          m = re.search(r'^[0-9a-zA-Z_]+ +([0-9]+) .*{}$'.format(pkg).encode(), d.encode(), re.MULTILINE)
          if m:
            pid = int(m.group(1))
            ui.info(f'detected target at pid: {pid}')

        async for l in dev.invoke_adb_streaming('logcat -T1'):
          l = l.rstrip()
          if not pid:
            m = re.search(r' ([0-9]+):{}'.format(pkg).encode(), l)
            if m:
              pid = int(m.group(1))
              ui.info(f'detected target at pid: {pid}')
          if self._watch_logcat:
            if self._target_only:
              if not (pid and re.search(r'\.[0-9]+? +{} +'.format(pid).encode(), l)):
                continue
            if re.search(self._watch_logcat, l):
              ui.info('log: {}'.format(l.decode('latin1')))
          if self._watch_intent and b'intent' in l:
            if re.search(self._watch_intent, l):
              ui.info('intent: {}'.format(l.decode('latin1')))
          m = re.search('([0-9]+) +?[0-9]+? I Frida +?: Listening on (.*)'.encode(), l)
          if m:
            gad_pid, gad_port = int(m.group(1)), m.group(2).decode()
            ui.success('detected frida-gadget listening on {} for pid {}{}'.format(gad_port, gad_pid, ' [target]' if pid == gad_pid else ''))

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

    async def _fs() -> None:
      if self._watch_fs:
        async for mode, path, md in self._watch_fs_mod_cont(delay=2.0):
          if re.search(self._watch_fs, path):
            ui.info('fs: {}: {} {}'.format(mode.decode(), md.decode(), path.decode()))

    try:
      from asyncio import gather
      ui.info('watching device (C-c to stop)')
      await gather(_log(), _ui(), _fs(), return_exceptions=True)
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

  async def _watch_fs_mod_cont(self, /, delay: float = 1.0) -> AsyncIterator[Tuple[bytes, bytes, bytes]]:
    from subprocess import CalledProcessError

    seen0: Dict[bytes, bytes] = dict()
    seen1: Dict[bytes, bytes] = dict()

    dev = AndroidDevice()
    try:
      async for msg in dev.invoke_adb_streaming(r'shell "while (true) do (find -H /storage -mtime -{thres}s -print0 | xargs -0 ls -nlld); echo \"*\"; sleep {delay}; done"'.format(delay=delay, thres=int(delay*3.))):
        msg = msg.rstrip()
        if not msg.startswith(b'*'):
          m = re.fullmatch(r'(.*00) (.+?)'.encode('latin1'), msg)
          if m:
            fn = m.group(2)
            metadata = m.group(1)
            seen0[fn] = metadata
        else:
          seen0set = frozenset(seen0.keys())
          seen1set = frozenset(seen1.keys())

          for k in seen0set - seen1set:
            yield b'add', k, seen0[k]

          for k in seen0set & seen1set:
            if seen0[k] != seen1[k]:
              yield b'mod', k, seen0[k]

          seen1.update(seen0)
          seen0.clear()
    except CalledProcessError as e:
      raise DumpFailedError(e)

  async def _exploit_fuzz_command(self, args: deque[str], am: bool = False) -> None:
    outfn: Optional[str] = None

    cmd = args.popleft()

    if not args:
      if am:
        ui.fatal('an "am" command line pattern required; try giving whatever you would to "adb shell am" (e.g. {} "start-activity .." ..)'.format(cmd))
      else:
        ui.fatal('command line pattern required; try giving you would to "adb shell"')

    pat = args.popleft()
    if am:
      pat = f'am {pat}'

    if args and not args[0].startswith('@'):
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    wordlist: Dict[str, List[str]] = dict()
    for name, fn in self._helper.get_effective_options(self._helper.get_modifiers(args)).items():
      if name.startswith('w'):
        name = name[1:]
        try:
          with open(fn, 'r') as f:
            wordlist[name] = [x.rstrip() for x in f]
        except OSError as e:
          ui.fatal(f'cannot open wordlist: {e}')

    if not wordlist:
      ui.fatal('need a wordlist (try @o:wNAME=FN)')

    ui.info('wordlist built: {} words in {} keys ({})'.format(sum([len(v) for v in wordlist.values()]), len(wordlist), ','.join(wordlist.keys())))

    def _expand(pat: str, wordlist: Mapping[str, List[str]]) -> Iterator[Tuple[int, int, str]]:
      tries = min(len(v) for v in wordlist.values())
      for nr in range(tries):
        d = {k:v[nr] for k,v in wordlist.items()}
        try:
          yield nr, tries, pat.format(*[], **d)
        except KeyError as e:
          ui.fatal(f'unknown wordlist specified: {e}')

    ui.info('starting fuzzing, opening log system-wide{}'.format(' [{}]'.format(outfn) if outfn else ''))

    dev = AndroidDevice()

    async def _log(outfn: Optional[str]) -> None:
      import sys
      nr = 0

      if not outfn:
        f = sys.stdout.buffer
      else:
        f = open(outfn, 'wb')

      try:
        async for l in dev.invoke_adb_streaming('logcat -T1'):
          f.write(l)
          nr += 1
          if outfn and nr % 256 == 0:
            ui.info(' ... captured: {}')
      finally:
        if outfn:
          f.close()

    async def _fuzz(pat: str, wordlist: Mapping[str, List[str]]) -> None:
      from asyncio import sleep
      from subprocess import CalledProcessError
      for nr, tries, t in _expand(pat, wordlist):
        await sleep(.05)
        prog = dict(nr=nr+1, max=tries, cmd=t)
        try:
          await dev.invoke_adb(f'shell {t}')
          ui.info('[{nr}/{max}] {cmd}'.format(**prog))
        except CalledProcessError as e:
          ui.failure('[{nr}/{max}] {cmd}: failed: {code}'.format(code=e.returncode, **prog))

    from asyncio import create_task, wait, FIRST_COMPLETED, ALL_COMPLETED
    task_log = create_task(_log(outfn))
    task_fuzz = create_task(_fuzz(pat, wordlist))

    done, pending = await wait([task_log, task_fuzz], return_when=FIRST_COMPLETED)
    for t in pending:
      t.cancel()
    done, _ = await wait([task_log, task_fuzz], return_when=ALL_COMPLETED)
    for t in done:
      exc = t.exception()
      if exc:
        ui.error('unhandled exception', exc=exc)

  async def _exploit_fuzz_intent(self, args: deque[str]) -> None:
    await self._exploit_fuzz_command(args, am=True)

class DumpFailedError(Exception):
  pass
