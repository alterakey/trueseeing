from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque
from pathlib import Path

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Mapping, List
  from trueseeing.api import CommandHelper, Command, CommandMap, OptionMap
  from trueseeing.core.ios.context import IPAContext
  from trueseeing.core.ios.device import IOSDevice

class EngageCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return EngageCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      '!!!':dict(e=self._run_frida_shell, n='!!!', d='attach frida to the foreground process', t={'ipa'}),
      'xs':dict(e=self._engage_frida_attach, n='xs[!] [config]', d='engage: attach frida scripts (!: force)', t={'ipa'}),
      'xs!':dict(e=self._engage_frida_attach, t={'ipa'}),
      'xst':dict(e=self._engage_frida_trace_call, n='xst[!] [init.js]', d='engage: trace calls (!: force)', t={'ipa'}),
      'xst!':dict(e=self._engage_frida_trace_call, t={'ipa'}),
    }

  def get_options(self) -> OptionMap:
    return {
      'wait':dict(n='wait', d='do not launch app [xs,xst]'),
      'attach':dict(n='attach', d='attach to the foremost app [xs,xst]'),
      'mod':dict(n='mod=MODULE,...', d='trace module (! to exclude) [xst]', t={'ipa'}),
      'fun':dict(n='fun=[MODULE!]FUNCTION,...', d='trace function (! to exclude) [xst]', t={'ipa'}),
      'offs':dict(n='offs=MODULE!OFFSET,...', d='trace offset [xst]', t={'ipa'}),
      'imp':dict(n='imp=INCLUDE_IMPORTS,...', d='trace program imports [xst]', t={'ipa'}),
      'mimp':dict(n='mimp=MODULE,...', d='trace module imports [xst]', t={'ipa'}),
      'objc':dict(n='objc=OBJC_METHOD,...', d='[iOS] trace objc method (! to exclude) [xst]', t={'ipa'}),
      'swif':dict(n='swif=SWIFT_FUNC,...', d='[iOS] trace swift function (! to exclude) [xst]', t={'ipa'}),
      'sym':dict(n='sym=SYMBOL,...', d='trace debug symbol [xst]', t={'ipa'}),
    }

  async def _engage_frida_attach(self, args: deque[str]) -> None:
    cmd = args.popleft()

    scripts = [a for a in args if not a.startswith('@')]

    force = cmd.endswith('!')
    wait = False
    attach = False

    for optname, optvalue in self._helper.get_effective_options(self._helper.get_modifiers(args)).items():
      if optname == 'wait':
        wait = True
      elif optname == 'attach':
        attach = True

    from time import time
    from trueseeing.core.ios.device import IOSDevice

    at = time()
    dev = IOSDevice()
    has_target = self._helper.get_target() is not None

    attacher = FridaAttacher(dev, [Path(s) for s in scripts])

    if attach or not has_target:
      if wait:
        await attacher.prompt()
      await attacher.attach()
    else:
      context = self._get_context()
      name = context.get_display_name()

      if force:
        ui.warn(f"killing {name}")
        await dev.invoke_frida_passthru(f"frida-kill -U {name}")

      ui.info(f"starting frida on {name}")

      if not wait:
        await attacher.spawn(name)
      else:
        await attacher.gate(name)

    ui.success("done ({t:.2f} sec.)".format(t=time() - at))

  async def _engage_frida_trace_call(self, args: deque[str]) -> None:
    cmd = args.popleft()

    scripts = [a for a in args if not a.startswith('@')]

    force = cmd.endswith('!')
    wait = False
    attach = False
    targets = dict()

    for optname, optvalue in self._helper.get_effective_options(self._helper.get_modifiers(args)).items():
      if optname == 'wait':
        wait = True
      elif optname == 'attach':
        attach = True
      elif optname in ['mod', 'fun', 'offs', 'imp', 'mimp', 'java', 'sym']:
        targets[optname] = optvalue.split(',')
      else:
        ui.warn(f'ignoring unknown opt: {optname}')

    from time import time
    from trueseeing.core.ios.device import IOSDevice

    at = time()
    dev = IOSDevice()
    has_target = self._helper.get_target() is not None

    attacher = FridaTracer(dev, targets, [Path(s) for s in scripts])

    if attach or not has_target:
      if wait:
        await attacher.prompt()
      await attacher.attach()
    else:
      context = self._get_context()
      name = context.get_display_name()

      if force:
        ui.warn(f"killing {name}")
        await dev.invoke_frida_passthru(f"frida-kill -U {name}")

      ui.info(f"starting frida on {name}")

      if not wait:
        await attacher.spawn(name)
      else:
        await attacher.gate(name)

    ui.success("done ({t:.2f} sec.)".format(t=time() - at))

  def _get_context(self) -> IPAContext:
    return self._helper.get_context().require_type('ipa')  # type:ignore[return-value]

  async def _run_frida_shell(self, args: deque[str]) -> None:
    from trueseeing.core.ios.device import IOSDevice

    dev = IOSDevice()
    attacher = FridaAttacher(dev, [], interactive=True)

    await attacher.attach()

class FridaAttacher:
  def __init__(self, dev: IOSDevice, scripts: List[Path], interactive: bool = False) -> None:
    self._dev = dev
    self._scripts = scripts
    self._interactive = interactive

  async def attach(self) -> None:
    from subprocess import CalledProcessError
    from asyncio import TimeoutError
    ui.info('attaching to the foreground process')
    try:
      await self._dev.invoke_frida_passthru("frida -UF {args}".format(
        args=self._format_args(),
      ))
    except (TimeoutError, CalledProcessError):
      ui.fatal('cannot attach to process')

  async def prompt(self) -> None:
    if ui.is_tty(stdin=True):
      import sys
      from trueseeing.core.ui import KeySeqDetector
      ui.info('launch the app on the device and press ENTER')
      async for ch in KeySeqDetector(sys.stdin).detect():
        if ch == b'\n':
          break

  async def spawn(self, name: str) -> None:
    from subprocess import CalledProcessError
    from asyncio import TimeoutError
    try:
      await self._dev.invoke_frida_passthru("frida -Uf {name} {args}".format(
        name=name,
        args=self._format_args(),
      ), timeout=3.)
    except (TimeoutError, CalledProcessError):
      ui.fatal('cannot attach to process (try @o:attach)')

  async def gate(self, name: str) -> None:
    from subprocess import CalledProcessError
    from asyncio import TimeoutError
    ui.info('waiting for the process; launch the app on the device in 60s')
    try:
      await self._dev.invoke_frida_passthru("frida -UW {name} {args}".format(
        name=name,
        args=self._format_args(),
      ), timeout=60.)
    except (TimeoutError, CalledProcessError):
      ui.fatal('cannot attach to process (try @o:attach)')

  def _format_args(self) -> str:
    from shlex import quote
    o: List[str] = []
    if not self._interactive:
      o.append('-q')
    for s in self._scripts:
      p = Path(s)
      if p.is_file():
        o.append(f"-l {quote(str(p))}")
      elif p.is_dir():
        o.extend([f"-l {quote(str(m))}" for m in p.rglob('*.js')])
      else:
        ui.warn(f"ignoring unknown path: {p}")
    return ' '.join(o)

# XXX refactor
class FridaTracer:
  def __init__(self, dev: IOSDevice, targets: Mapping[str, List[str]], scripts: List[Path]) -> None:
    self._dev = dev
    self._targets = targets
    self._scripts = scripts

  async def attach(self) -> None:
    from subprocess import CalledProcessError
    from asyncio import TimeoutError
    ui.info('attaching to the foreground process')
    try:
      await self._dev.invoke_frida_passthru("frida-trace -UF {args}".format(
        args=self._format_args(),
      ))
    except (TimeoutError, CalledProcessError):
      ui.fatal('cannot attach to process')

  async def prompt(self) -> None:
    if ui.is_tty(stdin=True):
      import sys
      from trueseeing.core.ui import KeySeqDetector
      ui.info('launch the app on the device and press ENTER')
      async for ch in KeySeqDetector(sys.stdin).detect():
        if ch == b'\n':
          break

  async def spawn(self, name: str) -> None:
    from subprocess import CalledProcessError
    from asyncio import TimeoutError
    try:
      await self._dev.invoke_frida_passthru("frida-trace -Uf {name} {args}".format(
        name=name,
        args=self._format_args(),
      ))
    except (TimeoutError, CalledProcessError):
      ui.fatal('cannot attach to process (try @o:attach)')

  async def gate(self, name: str) -> None:
    from subprocess import CalledProcessError
    from asyncio import TimeoutError
    ui.info('waiting for the process; launch the app on the device in 60s')
    try:
      await self._dev.invoke_frida_passthru("frida-trace -UW {name} {args}".format(
        name=name,
        args=self._format_args(),
      ))
    except (TimeoutError, CalledProcessError):
      ui.fatal('cannot attach to process (try @o:attach)')

  def _format_args(self) -> str:
    from shlex import quote
    from trueseeing.core.env import get_frida_trace_port
    o = ['-d']

    port = get_frida_trace_port()
    if port:
      o.append('--ui-port {port}'.format(port=port))

    for s in self._scripts:
      p = Path(s)
      if p.is_file():
        o.append(f"-S {quote(str(p))}")
      elif p.is_dir():
        o.extend([f"-S {quote(str(m))}" for m in p.rglob('*.js')])
      else:
        ui.warn(f"ignoring unknown path: {p}")
    opts = dict(mod='IX', fun='ix', offs='a', imp='T', mimp='t', objc='mM', swif='yY', sym='s')
    for k, v in self._targets.items():
      assert k in opts
      for t0 in v:
        if t0.startswith('!') and len(opts[k]) > 1:
          o.append(f'-{opts[k][1]} {quote(t0[1:])}')
        else:
          o.append(f'-{opts[k][0]} {quote(t0)}')
    return ' '.join(o)
