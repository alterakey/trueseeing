from __future__ import annotations
from typing import TYPE_CHECKING

from code import InteractiveConsole
from collections import deque
import asyncio
from functools import cache
from shlex import shlex
import sys
import re
from trueseeing.core.context import FileOpener
from trueseeing.core.ui import ui, CoreProgressReporter
from trueseeing.core.exc import FatalError, InvalidSchemaError

if TYPE_CHECKING:
  from typing import Mapping, Optional, Any, NoReturn, List, Dict, Awaitable, Type, Set, Iterator
  from prompt_toolkit.styles import Style
  from trueseeing.core.context import ContextType
  from trueseeing.api import Entry, Command, CommandHelper, CommandEntry, CommandPatternEntry, ModifierEntry, OptionEntry, ConfigMap, ModifierEvent, CommandMap, CommandPatternMap, OptionMap, ModifierMap

class InspectMode:
  def do(
      self,
      target: Optional[str],
      batch: bool = False,
      cmdlines: List[str] = [],
      abort_on_errors: bool = False,
      force_opener: Optional[str] = None,
  ) -> NoReturn:
    try:
      try:
        if ui.is_tty():
          ui.enter_inspect()
        with CoreProgressReporter().scoped():
          self._do(target, batch, cmdlines, abort_on_errors, force_opener)
      finally:
        if ui.is_tty():
          ui.exit_inspect()
    except QuitSession as e:
      sys.exit(e.code)
    else:
      sys.exit(0)

  def _do(
      self,
      target: Optional[str],
      batch: bool,
      cmdlines: List[str],
      abort_on_errors: bool,
      force_opener: Optional[str],
  ) -> int:
    runner = Runner(target, abort_on_errors=abort_on_errors, force_opener=force_opener)

    for line in cmdlines:
      asyncio.run(LambdaConsole._worker(runner.run(line)))

    if batch:
      return 0

    if not ui.is_tty(stdin=True):
      ui.fatal('requires a tty')

    asyncio.run(runner.greeting())

    ps1, ps2 = getattr(sys, 'ps1', None), getattr(sys, 'ps2', None)
    try:
      LambdaConsole(locals=locals(), runner=runner).interact(banner='', exitmsg='')
      return 0
    finally:
      sys.ps1, sys.ps2 = ps1, ps2

class LambdaConsole(InteractiveConsole):
  def __init__(self, /, runner: Runner, locals: Optional[Mapping[str, Any]] = None) -> None:
    super().__init__(locals=locals, filename='<input>')
    from prompt_toolkit import PromptSession
    self._sess: Any = PromptSession()
    self._runner = runner

  def runsource(self, source: str, filename: Optional[str]=None, symbol: Optional[str]=None) -> bool:
    try:
      asyncio.run(self._worker(self._runner.run(source)))
    except FatalError:
      pass
    return False

  def raw_input(self, prompt: str = "") -> str:
    target = self._runner.get_target()
    return self._sess.prompt(  # type: ignore[no-any-return]
      message=[('class:p', f'ts[{target}]> ' if target else 'ts> ')],
      prompt_continuation=[('class:p', '... ')],
      style=self._get_prompt_style(),
    )

  @cache
  def _get_prompt_style(self) -> Style:
    from prompt_toolkit.styles import Style
    return Style.from_dict({'p': '#888800'})

  @classmethod
  async def _worker(cls, coro: Any) -> None:
    tasks = [asyncio.create_task(coro)]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
      t.cancel()
    if pending:
      _, _ = await asyncio.wait(pending)
    for t in done:
      if not t.cancelled():
        x = t.exception()
        if x:
          assert isinstance(x, Exception)
          if isinstance(x, QuitSession):
            raise x
          elif not isinstance(x, FatalError):
            ui.fatal('unhandled exception', exc=x)

class QuitSession(Exception):
  def __init__(self, code: int, *args: Any, **kwargs: Any) -> None:
    super().__init__(code, *args, **kwargs)
    self.code = code

class SessionCommands:
  _cmds: Dict[str, Dict[str, CommandEntry]]
  _cmdpats: Dict[str, Dict[str, CommandPatternEntry]]
  _mods: Dict[str, Dict[str, ModifierEntry]]
  _opts: Dict[str, Dict[str, OptionEntry]]
  _typ: Optional[Set[ContextType]] = None

  def __init__(self) -> None:
    from trueseeing.core.config import Configs
    self._cmds = {}
    self._cmdpats = {}
    self._mods = {}
    self._opts = {}
    self._confbag = Configs.get().bag

  def add_cmds(self, cmap: CommandMap) -> None:
    for k, v in cmap.items():
      self._cmds[k] = {p:v for p in v.get('t', {''})}

  def add_cmdpats(self, cmap: CommandPatternMap) -> None:
    for k, v in cmap.items():
      self._cmdpats[k] = {p:v for p in v.get('t', {''})}

  def add_mods(self, cmap: ModifierMap) -> None:
    for k, v in cmap.items():
      self._mods[k] = {p:v for p in v.get('t', {''})}

  def add_opts(self, cmap: OptionMap) -> None:
    for k, v in cmap.items():
      self._opts[k] = {p:v for p in v.get('t', {''})}

  def add_configs(self, cmap: ConfigMap) -> None:
    self._confbag.update(cmap)

  def get_cmds(self) -> CommandMap:
    return self._slice(self._cmds) # type:ignore[no-any-return]

  def get_cmdpats(self) -> CommandPatternMap:
    return self._slice(self._cmdpats) # type:ignore[no-any-return]

  def get_mods(self) -> ModifierMap:
    return self._slice(self._mods) # type:ignore[no-any-return]

  def get_opts(self) -> OptionMap:
    return self._slice(self._opts) # type:ignore[no-any-return]

  def get_configs(self) -> ConfigMap:
    return self._confbag

  def _slice(self, target: Any) -> Any:
    o: Dict[str, Any] = dict()
    for k,pv in target.items():
      for p in self._get_matches(pv.keys()):
        o[k] = pv[p]
        break
    return o

  def _get_matches(self, ks: Iterator[str]) -> Iterator[str]:
    for k in sorted(ks, key=len):
      if self._typ is None:
        yield k
      elif not k:
        yield k
      elif any([re.match(k, t) for t in self._typ]):
        yield k

  def set_type(self, typ: Optional[Set[ContextType]]) -> None:
    self._typ = typ

class Runner:
  _sc: SessionCommands
  _quiet: bool = False
  _verbose: bool = False
  _target: Optional[str]
  _abort_on_errors: bool = False
  _helper: CommandHelper
  _loglevel: int

  def __init__(self, target: Optional[str], *, abort_on_errors: bool = False, force_opener: Optional[str] = None) -> None:
    self._target = target
    self._sc = SessionCommands()
    self._sc.add_cmds({
      '?':dict(e=self._help, n='?', d='help'),
      '?@?':dict(e=self._help_mod, n='?@?', d='modifier help'),
      '?o?':dict(e=self._help_opt, n='?o?', d='options help'),
      '?f?':dict(e=self._help_formats, n='?f?', d='supported file formats'),
      '!':dict(e=self._shell, n='!', d='shell'),
      'o':dict(e=self._set_target, n='o /path/to/target', d='set target file'),
      'q':dict(e=self._quit, n='q', d='quit'),
    })
    self._sc.add_mods({
      'o':dict(n='@o:option', d='pass option', e=None),
      'gs':dict(n='@gs:<int>[kmKM]', d='set graph size limit', e=None),
    })
    self._sc.add_configs(self._get_configs())
    if abort_on_errors:
      self._abort_on_errors = True

    self._helper = CommandHelperImpl(self, force_opener=force_opener)
    self._loglevel = ui.level

    self._init_cmds()

  def _init_cmds(self) -> None:
    from trueseeing.core.ext import Extension
    from trueseeing.app.cmd import discover

    for clazz in discover():
      self._register_cmd(clazz)

    for clazz in Extension.get().get_commands():
      self._register_cmd(clazz)

  def _register_cmd(self, clazz: Type[Command]) -> None:
    t = clazz.create(self._helper)
    self._sc.add_cmds(t.get_commands())
    self._sc.add_cmdpats(t.get_command_patterns())
    self._sc.add_mods(t.get_modifiers())
    self._sc.add_opts(t.get_options())
    self._sc.add_configs(t.get_configs())

  def get_target(self) -> Optional[str]:
    return self._target

  def _get_configs(self) -> ConfigMap:
    return {
      'core.debug':dict(g=self._config_get_debug, s=self._config_set_debug, n='core.debug', d='toggle debug mode (true, false)'),
      'core.quiet':dict(g=self._config_get_quiet, s=self._config_set_quiet, n='core.quiet', d='toggle quiet mode (true, false)'),
    }

  def _config_get_debug(self) -> str:
    return 'true' if (ui.level == ui.DEBUG) else 'false'

  def _config_set_debug(self, v: Any) -> None:
    try:
      self._loglevel = dict(true=ui.DEBUG, false=ui.INFO)[v]
      self._reset()
    except KeyError:
      ui.fatal(f'invalid value: {v}')

  def _config_get_quiet(self) -> str:
    return 'true' if (ui.level == ui.WARN) else 'false'

  def _config_set_quiet(self, v: Any) -> None:
    try:
      self._loglevel = dict(true=ui.WARN, false=ui.INFO)[v]
    except KeyError:
      ui.fatal(f'invalid value: {v}')

  async def greeting(self) -> None:
    try:
      from trueseeing import __version__ as version
      ui.success(f"Trueseeing {version}")
    finally:
      self._reset()

  async def run(self, s: str) -> None:
    try:
      try:
        await self._run(s)
      except InvalidSchemaError:
        ui.fatal('invalid schema detected, forced reanalysis needed (try a!)')
    finally:
      self._reset()

  async def _run(self, s: str) -> None:
    if not await self._run_raw(s):
      o: deque[str] = deque()
      lex = shlex(s, posix=True, punctuation_chars=';')
      lex.wordchars += '@:,=!$'
      for t in lex:
        if re.fullmatch(';+', t):
          if not await self._run_cmd(o, line=None):
            ui.error('invalid command, type ? for help')
          o.clear()
        else:
          o.append(t)
      if o:
        if not await self._run_cmd(o, line=s):
          ui.error('invalid command, type ? for help')

  async def _run_raw(self, line: str) -> bool:
    ent: Any = None
    cmdpats = self._sc.get_cmdpats()
    for pat in [k for k,v in cmdpats.items() if v.get('raw')]:
      m = re.match(pat, line)
      if m:
        ent = cmdpats[pat]
        if m.end() < (len(line) - 1):
          ui.warn('ignoring trailer: {}'.format(line[m.end():]))
        break
    if ent is None:
      return False
    else:
      assert m is not None
      await self._as_cmd(ent['e'](line=m.group(0)))
      return True

  async def _run_cmd(self, tokens: deque[str], line: Optional[str]) -> bool:
    ent: Any = None
    cmdpats = self._sc.get_cmdpats()
    cmds = self._sc.get_cmds()
    if line is not None:
      for pat in [k for k,v in cmdpats.items() if not v.get('raw')]:
        m = re.match(pat, line)
        if m:
          ent = cmdpats[pat]
          break

    if ent is None:
      c = tokens[0]
      if c in cmds:
        ent = cmds[c]

    if ent is None:
      return False
    else:
      await self._notify_modifiers('begin', tokens)
      try:
        await self._as_cmd(ent['e'](args=tokens))
        return True
      finally:
        await self._notify_modifiers('end', tokens)

  async def _as_cmd(self, coro: Awaitable[Any]) -> None:
    try:
      try:
        await coro
      except KeyboardInterrupt:
        ui.fatal('interrupted')
    except FatalError:
      if self._abort_on_errors:
        raise QuitSession(1)

  async def _notify_modifiers(self, ev: ModifierEvent, tokens: deque[str]) -> None:
    for mod in self._get_modifiers(tokens):
      typ, val = mod[1:].split(':', maxsplit=1)

      for et, ee in self._sc.get_mods().items():
        if et == typ:
          if ee['e'] is not None:
            await ee['e'](ev, val)

  def _get_modifiers(self, args: deque[str]) -> List[str]:
    o = []
    for m in args:
      if m.startswith('@'):
        o.append(m)
    return o

  def _reset(self, debug:bool = False) -> None:
    ui.set_level(self._loglevel)
    self._sc.set_type(self._helper.get_context_type())

  async def _help(self, args: deque[str]) -> None:
    ents: Dict[str, Entry] = dict()
    ents.update(self._sc.get_cmds())
    ents.update(self._sc.get_cmdpats())  # type: ignore[arg-type]
    await self._help_on('Commands:', ents)

  async def _help_mod(self, args: deque[str]) -> None:
    await self._help_on('Modifiers:', self._sc.get_mods()) # type: ignore[arg-type]

  async def _help_opt(self, args: deque[str]) -> None:
    await self._help_on('Options:', self._sc.get_opts()) # type: ignore[arg-type]

  async def _help_on(self, topic: str, entries: Dict[str, Entry]) -> None:
    ui.success(topic)
    if entries:
      width = (2 + max([len(e.get('d', '')) for e in entries.values()]) // 4) * 4
      for k in sorted(entries):
        e = entries[k]
        if 'n' in e:
          ui.stderr(
            f'{{n:<{width}s}}{{d}}'.format(n=e['n'], d=e['d'])
          )

  async def _help_formats(self, args: deque[str]) -> None:
    from trueseeing.core.context import FileOpener
    ui.success('File formats:')
    formats = list(FileOpener().get_formats())
    width = 2 + max([len(e['n']) for e in formats])
    for e in formats:
      ui.stderr(
        f'{{n:<{width}s}}{{d}}'.format(n=e['n'], d=e['d'])
      )

  async def _shell(self, args: deque[str]) -> None:
    from trueseeing.core.env import get_shell
    from asyncio import create_subprocess_exec
    await (await create_subprocess_exec(get_shell())).wait()

  async def _quit(self, args: deque[str]) -> None:
    raise QuitSession(0)

  async def _set_target(self, args: deque[str]) -> None:
    _ = args.popleft()

    if not args:
      ui.fatal('need path')

    self._target = args.popleft()

class CommandHelperImpl:
  def __init__(self, runner: Runner, force_opener: Optional[str] = None) -> None:
    self._r = runner
    self._opener = FileOpener(force_opener=force_opener)
    self._confbag = self._r._sc.get_configs()

  def get_target(self) -> Optional[str]:
    return self._r.get_target()

  def require_target(self, msg: Optional[str] = None) -> str:
    t = self.get_target()
    if t is None:
      ui.fatal(msg if msg else 'need target')
    return t

  def get_context_type(self) -> Optional[Set[ContextType]]:
    from trueseeing.core.exc import InvalidFileFormatError
    t = self.get_target()
    if not t:
      return None
    try:
      return self._opener.get_context(t).type
    except InvalidFileFormatError:
      return set()

  def get_context(self, typ: Optional[ContextType] = None) -> Any:
    from trueseeing.core.exc import InvalidFileFormatError
    try:
      c = self._opener.get_context(self.require_target())
      if typ is not None:
        ui.warn('get_context(typ): deprecated, use get_context().request_type(...)', onetime=True)
        c.require_type(typ)
      return c
    except InvalidFileFormatError:
      ui.fatal('cannot recognize format')

  async def get_context_analyzed(self, typ: Optional[ContextType] = None, *, level: int = 3) -> Any:
    if typ is None:
      ui.warn('get_context_analyzed: deprecated; use get_context().analyze(...)', onetime=True)
    else:
      ui.warn('get_context_analyzed(typ): deprecated; use get_context().request_type(...).analyze(...)', onetime=True)

    c = self.get_context()
    if typ:
      c.require_type(typ)
    await c.analyze(level=level)
    return c

  def decode_analysis_level(self, level: int) -> str:
    analysislevelmap = {0:'no', 1: 'minimally', 2: 'lightly', 3:'marginally', 4:'fully'}
    return analysislevelmap.get(level, '?')

  async def run(self, s: str) -> None:
    await self._r._run(s)

  async def run_cmd(self, tokens: deque[str], line: Optional[str]) -> bool:
    return await self._r._run_cmd(tokens, line)

  def get_modifiers(self, args: deque[str]) -> List[str]:
    return self._r._get_modifiers(args)

  def get_effective_options(self, mods: List[str]) -> Mapping[str, str]:
    o = {}
    for m in mods:
      if m.startswith('@o:'):
        for a in m[3:].split(','):
          c: List[str] = a.split('=', maxsplit=1)
          if len(c) == 1:
            o[c[0]] = c[0]
          else:
            o[c[0]] = c[1]
    return o

  def get_graph_size_limit(self, mods: List[str]) -> Optional[int]:
    for m in mods:
      if m.startswith('@gs:'):
        c = m[4:]
        s = re.search(r'[km]$', c.lower())
        if s:
          return int(m[4:-1]) * dict(k=1024, m=1024*1024)[s.group(0)]
        else:
          return int(m[4:])
    return None

  def get_config(self, k: str) -> Any:
    from trueseeing.core.exc import InvalidConfigKeyError
    try:
      e = self._confbag[k]
    except KeyError:
      raise InvalidConfigKeyError()
    else:
      return e['g']()

  def set_config(self, k: str, v: Any) -> None:
    from trueseeing.core.exc import InvalidConfigKeyError
    try:
      e = self._confbag[k]
    except KeyError:
      raise InvalidConfigKeyError()
    else:
      e['s'](v)
