from __future__ import annotations
from typing import TYPE_CHECKING

import sys
from functools import cache
from trueseeing.core.exc import FatalError

if TYPE_CHECKING:
  from typing import NoReturn, Optional, TextIO, Set, Any
  from typing_extensions import Final

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


ui = UI()
