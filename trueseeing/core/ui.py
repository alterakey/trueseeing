from __future__ import annotations
from typing import TYPE_CHECKING

import sys
from contextlib import contextmanager
from functools import cache
from pubsub import pub
from trueseeing.core.exc import FatalError

if TYPE_CHECKING:
  from typing import NoReturn, Optional, TextIO, Set, Any, Iterator
  from typing_extensions import Final
  from progressbar import ProgressBar
  from trueseeing.core.model.issue import Issue

class UI:
  DEBUG: Final = 0
  INFO: Final = 1
  WARN: Final = 2
  ERROR: Final = 3
  CRITICAL: Final = 4
  FATAL: Final = 5

  level = DEBUG
  is_debugging = False
  _is_inspecting = False

  _seen: Set[str] = set()

  def is_tty(self, stdin: bool = False) -> bool:
    from os import isatty
    if not stdin:
      return isatty(sys.stderr.fileno())
    else:
      return isatty(sys.stdin.fileno())

  def enter_inspect(self) -> None:
    self._is_inspecting = True

  def exit_inspect(self) -> None:
    self._is_inspecting = False

  def set_level(self, level: int) -> None:
    self.level = level
    self.is_debugging = (self.level == self.DEBUG)

  # XXX: check color capability on our own because we are coloring stderr -- termcolor cares stdout only.
  @cache
  def colored(self, x: str, **kw: Any) -> str:
    from termcolor import colored
    return colored(x, force_color=self._can_do_colour_stderr(), **kw)

  def bullet(self, what: str) -> str:
    if not self._is_inspecting:
      return ''
    if what == 'critical':
      return self.colored('[!] ', color='red', attrs=('bold',))
    elif what == 'error':
      return self.colored('[-] ', color='red', attrs=('bold',))
    elif what == 'warn':
      return self.colored('[*] ', color='yellow', attrs=('bold',))
    elif what == 'info':
      return self.colored('[*] ', color='blue', attrs=('bold',))
    elif what == 'debug':
      return self.colored('[.] ', color='grey', attrs=('bold',))
    elif what == 'success':
      return self.colored('[+] ', color='green', attrs=('bold',))
    elif what == 'failure':
      return self.colored('[-] ', color='red', attrs=('bold',))
    assert False, f'invalid type of bullet: {what}'

  def fatal(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> NoReturn:
    if not self._is_inspecting:
      self.stderr(f'fatal: {msg}', nl=nl, ow=ow, onetime=onetime, exc=exc)
    else:
      self.failure(f'fatal: {msg}', nl=nl, ow=ow, onetime=onetime, exc=exc)
    raise FatalError()

  def critical(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> None:
    if self.level <= self.CRITICAL:
      self.stderr(self._format_msg(msg, 'critical'), nl=nl, ow=ow, onetime=onetime, exc=exc)

  def error(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> None:
    if self.level <= self.ERROR:
      self.stderr(self._format_msg(msg, 'error'), nl=nl, ow=ow, onetime=onetime, exc=exc)

  def warn(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> None:
    if self.level <= self.WARN:
      self.stderr(self._format_msg(msg, 'warn'), nl=nl, ow=ow, onetime=onetime, exc=exc)

  def info(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> None:
    if self.level <= self.INFO:
      self.stderr(self._format_msg(msg, 'info'), nl=nl, ow=ow, onetime=onetime, exc=exc)

  def debug(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> None:
    if self.level <= self.DEBUG:
      self.stderr(self._format_msg(msg, 'debug'), nl=nl, ow=ow, onetime=onetime, exc=exc)

  def success(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> None:
    self.stderr(self._format_msg(msg, 'success'), nl=nl, ow=ow, onetime=onetime, exc=exc)

  def failure(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> None:
    self.stderr(self._format_msg(msg, 'failure'), nl=nl, ow=ow, onetime=onetime, exc=exc)

  def stdout(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> None:
    if onetime:
      if msg in self._seen:
        return
      else:
        self._seen.add(msg)
    if ow:
      sys.stdout.write('\r')
    sys.stdout.write(msg)
    if nl:
      sys.stdout.write('\n')
    sys.stdout.flush()
    if exc is not None:
      self._format_exception(sys.stdout, exc, nl=nl, ow=ow)

  def stderr(self, msg: str, nl: bool = True, ow: bool = False, onetime: bool = False, exc: Optional[Exception] = None) -> None:
    if onetime:
      if msg in self._seen:
        return
      else:
        self._seen.add(msg)
    if ow:
      sys.stderr.write('\r')
    sys.stderr.write(msg)
    if nl:
      sys.stderr.write('\n')
    sys.stderr.flush()
    if exc is not None:
      self._format_exception(sys.stderr, exc, nl=nl, ow=ow)

  def _format_exception(self, f: TextIO, exc: Exception, nl: bool = True, ow: bool = False) -> None:
    from traceback import format_exception
    if ow:
      f.write('\r')
    f.write(''.join(format_exception(type(exc), exc, exc.__traceback__)))
    if nl:
      f.write('\n')

  def _format_msg(self, msg: str, flagtyp: str, **kw: Any) -> str:
    return '{flag}{msg}'.format(flag=self.bullet(flagtyp), msg=msg)

  # termcolor 2.4 compatible color capability checker
  @cache
  def _can_do_colour_stderr(self) -> bool:
    from io import UnsupportedOperation
    from os import environ, isatty

    if "ANSI_COLORS_DISABLED" in environ:
      return False
    if "NO_COLOR" in environ:
      return False
    if "FORCE_COLOR" in environ:
      return True

    if environ.get("TERM") == "dumb":
      return False
    if not hasattr(sys.stderr, "fileno"):
      return False

    try:
      return isatty(sys.stderr.fileno())
    except UnsupportedOperation:
      return sys.stderr.isatty()

class CoreProgressReporter:
  _bar_lift: Optional[ProgressBar] = None
  _bar_disasm: Optional[ProgressBar] = None
  _bar_asm: Optional[ProgressBar] = None
  _bar_analysis: Optional[ProgressBar] = None

  @contextmanager
  def scoped(self) -> Iterator[None]:
    submap = {
      'progress.core.context.disasm.begin':self._core_context_disasm_begin,
      'progress.core.context.disasm.done':self._core_context_disasm_done,
      'progress.core.asm.lift.begin':self._core_asm_lift_begin,
      'progress.core.asm.lift.update':self._core_asm_lift_update,
      'progress.core.asm.lift.done':self._core_asm_lift_done,
      'progress.core.asm.disasm.begin':self._core_asm_disasm_begin,
      'progress.core.asm.disasm.update':self._core_asm_disasm_update,
      'progress.core.asm.disasm.done':self._core_asm_disasm_done,
      'progress.core.asm.asm.begin':self._core_asm_asm_begin,
      'progress.core.asm.asm.update':self._core_asm_asm_update,
      'progress.core.asm.asm.done':self._core_asm_asm_done,
      'progress.core.analysis.smali.begin':self._core_analysis_smali_begin,
      'progress.core.analysis.smali.analyzing':self._core_analysis_smali_analyzing,
      'progress.core.analysis.smali.analyzed':self._core_analysis_smali_analyzed,
      'progress.core.analysis.smali.summary':self._core_analysis_smali_summary,
      'progress.core.analysis.smali.finalizing':self._core_analysis_smali_finalizing,
      'progress.core.analysis.smali.done':self._core_analysis_smali_done,
    }
    try:
      for k, v in submap.items():
        pub.subscribe(v, k)
      yield None
    finally:
      for k, v in submap.items():
        pub.unsubscribe(v, k)
      pass

  def _core_context_disasm_begin(self) -> None:
    ui.info('analyze: disassembling... ', nl=False)

  def _core_asm_lift_begin(self) -> None:
    if ui.is_tty():
      from progressbar import ProgressBar, RotatingMarker
      self._bar_lift = ProgressBar(widgets=[
        ui.bullet('info'),
        'analyze: disassembling... ',
        RotatingMarker()   # type:ignore[no-untyped-call]
      ])
    else:
      self._bar_lift = None

  def _core_asm_lift_update(self) -> None:
    if self._bar_lift is not None:
      self._bar_lift.next()   # type:ignore[no-untyped-call]

  def _core_asm_lift_done(self) -> None:
    if self._bar_lift:
      self._bar_lift.finish(end='\r')   # type:ignore[no-untyped-call]

  def _core_asm_disasm_begin(self) -> None:
    if ui.is_tty():
      from progressbar import ProgressBar, RotatingMarker
      self._bar_disasm = ProgressBar(widgets=[
        ui.bullet('info'),
        'disassemble: disassembling... ',
        RotatingMarker()   # type:ignore[no-untyped-call]
      ])
    else:
      ui.info('disassemble: disassembling... ')
      self._bar_disasm = None

  def _core_asm_disasm_update(self) -> None:
    if self._bar_disasm is not None:
      self._bar_disasm.next()   # type:ignore[no-untyped-call]

  def _core_asm_disasm_done(self) -> None:
    if self._bar_disasm is not None:
      ui.info('disassemble: disassembling... done.', ow=True)
    else:
      ui.info('disassemble: done')

  def _core_asm_asm_begin(self) -> None:
    if ui.is_tty():
      from progressbar import ProgressBar, RotatingMarker
      self._bar_asm = ProgressBar(widgets=[
        ui.bullet('info'),
        'assemble: assembling... ',
        RotatingMarker()   # type:ignore[no-untyped-call]
      ])
    else:
      ui.info('assemble: assembling... ')
      self._bar_asm = None

  def _core_asm_asm_update(self) -> None:
    if self._bar_asm is not None:
      self._bar_asm.next()   # type:ignore[no-untyped-call]

  def _core_asm_asm_done(self) -> None:
    if self._bar_asm is not None:
      ui.info('assemble: assembling... done.', ow=True)
    else:
      ui.info('assemble: done')

  def _core_context_disasm_done(self) -> None:
    ui.info('analyze: disassembling... done.', ow=True)

  def _core_analysis_smali_begin(self, total: int) -> None:
    if ui.is_tty():
      from progressbar import ProgressBar, Percentage, GranularBar, SimpleProgress, ETA
      self._bar_analysis = ProgressBar(
        max_value=total,
        widgets=[
          ui.bullet('info'),
          'analyze: analyzing... ',
          Percentage(), ' ',  # type:ignore[no-untyped-call]
          GranularBar(), ' ',  # type:ignore[no-untyped-call]
          SimpleProgress(format='%(value_s)s/%(max_value_s)s'), ' ',   # type:ignore[no-untyped-call]
          '(', ETA(), ')'   # type:ignore[no-untyped-call]
        ]
      )
    else:
      self._bar_analysis = None

  def _core_analysis_smali_analyzing(self, nr: int) -> None:
    if self._bar_analysis is not None:
      self._bar_analysis.update(nr)   # type:ignore[no-untyped-call]
    else:
      if (nr % 128) == 0:
        ui.info(f"analyze: analyzing ... {nr} classes")

  def _core_analysis_smali_analyzed(self) -> None:
    if self._bar_analysis is not None:
      self._bar_analysis.finish()   # type:ignore[no-untyped-call]

  def _core_analysis_smali_summary(self, ops: Optional[int] = None, classes: Optional[int] = None, methods: Optional[int] = None) -> None:
    if self._bar_analysis:
      o: str = ''
      tail: str = ' '*20
      if ops is None:
        o += f'ops ... {tail}'
      else:
        o += f'{ops} ops, '
        if classes is None:
          o += f'classes ... {tail}'
        else:
          o += f'{classes} classes, '
          if methods is None:
            o += f'methods ... {tail}'
          else:
            o += f'{methods} methods.'
      ui.info(f"analyze: got {o}", nl=(methods is not None), ow=True)
    else:
      if methods is not None:
        ui.info(f"analyze: methods: {methods}")
      elif classes is not None:
        ui.info(f"analyze: classes: {classes}")
      elif ops is not None:
        ui.info(f"analyze: ops: {ops}")

  def _core_analysis_smali_finalizing(self) -> None:
    ui.info("analyze: finalizing")

  def _core_analysis_smali_done(self, t: float) -> None:
    ui.info(f"analyze: done ({t:.02f} sec)")

class FileTransferProgressReporter:
  _bar: Optional[ProgressBar]
  def __init__(self, desc: str) -> None:
    self._done = False
    self._desc = desc

  @contextmanager
  def scoped(self) -> Iterator[FileTransferProgressReporter]:
    try:
      self.start()
      yield self
    finally:
      if self._bar is not None and not self._done:
        self._bar.finish()  # type: ignore[no-untyped-call]

  def using_bar(self) -> bool:
    return self._bar is not None

  def start(self) -> None:
    if ui.is_tty():
      from progressbar import ProgressBar, Counter, RotatingMarker
      self._bar = ProgressBar(widgets=[
        ui.bullet('info'),
        f'{self._desc}... ',
        Counter(), ' ',   # type:ignore[no-untyped-call]
        RotatingMarker()   # type:ignore[no-untyped-call]
      ])
      self._bar.start() # type:ignore[no-untyped-call]
    else:
      ui.info(self._desc)
      self._bar = None

  def update(self, nr: int) -> None:
    if self._bar is not None:
      self._bar.update(nr) # type: ignore[no-untyped-call]
    else:
      ui.info(f' .. {nr} files')

  def done(self) -> None:
    if self._bar is not None:
      self._bar.finish(end='\r')  # type: ignore[no-untyped-call]
      ui.info(f'{self._desc}... done.' + (' '*16), ow=True)
    else:
      ui.info(f'{self._desc}... done.')
    self._done = True

class ScanProgressReporter:
  def __init__(self) -> None:
    from trueseeing.core.report import ConsoleNoter
    self._CN = ConsoleNoter()

  @contextmanager
  def scoped(self) -> Iterator[None]:
    submap = {
      'issue':self._issue,
    }
    try:
      for k, v in submap.items():
        pub.subscribe(v, k)
      yield None
    finally:
      for k, v in submap.items():
        pub.unsubscribe(v, k)
      pass

  def _issue(self, issue: Issue) -> None:
    self._CN.note(issue)


ui = UI()
