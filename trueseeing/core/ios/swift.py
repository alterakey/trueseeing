from __future__ import annotations
from typing import TYPE_CHECKING
from contextlib import asynccontextmanager
from functools import cache
from os import read, write, close

if TYPE_CHECKING:
  from aiohttp import ClientSession
  from typing import Protocol, Optional, AsyncIterator, AsyncContextManager, Tuple
  from typing_extensions import Self

  class SwiftDemanglerImpl(Protocol):
    def scoped(self) -> AsyncContextManager[Self]: ...
    async def resolve(self, q: str) -> str: ...

class SwiftDemangler:
  @classmethod
  def get(cls, simplify: bool = False) -> SwiftDemanglerImpl:
    if _find_swift_demangler():
      return _Local(simplify)
    else:
      return _Remote(simplify)

class _Local:
  _f: Optional[Tuple[int, int]]

  def __init__(self, simplify: bool = False):
    from asyncio import Lock, get_running_loop
    from threading import Event
    self._l = get_running_loop()
    self._f = None
    self._w = Event()
    self._s = Lock()
    self._simp = simplify

  @asynccontextmanager
  async def scoped(self) -> AsyncIterator[Self]:
    try:
      yield self
    finally:
      if self._f:
        for n in self._f:
          close(n)

  async def _boot(self) -> None:
    def _do() -> None:
      from subprocess import Popen
      from os import openpty
      assert self._f is None
      i0, i1 = openpty()
      o0, o1 = openpty()
      with Popen(self._get_cmdline(), shell=True, bufsize=0, stdin=i1, stdout=o1):
        self._f = (i0, o0)
        self._w.set()
      self._w.clear()
      self._f = None

    if not self._w.is_set():
      self._l.run_in_executor(None, _do)
      self._w.wait()

  async def resolve(self, q: str) -> str:
    async with self._s:
      await self._boot()
      assert self._f is not None
      write(self._f[0], q.encode() + b'\n')
      o = bytearray()
      while not o.endswith(b'\n'):
        o = o + read(self._f[1], 1024)
      return o.rstrip().decode()

  def _get_cmdline(self) -> str:
    path = _find_swift_demangler()
    assert path
    return '{}{}'.format(
      path,
      ' -simplified' if self._simp else ''
    )

class _Remote:
  _sess: Optional[ClientSession] = None

  def __init__(self, simplify: bool = False):
    from trueseeing.core.env import get_swift_demangler_url
    self._url = '{base}{prefix}'.format(base=get_swift_demangler_url(), prefix='/s/' if simplify else '/')

  @asynccontextmanager
  async def scoped(self) -> AsyncIterator[Self]:
    from aiohttp import ClientSession, ClientConnectionError
    async with ClientSession() as sess:
      try:
        async with sess.get(self._url + 'a'):
          pass
        self._sess = sess
      except ClientConnectionError:
        from trueseeing.core.ui import ui
        ui.warn('swift demangler is not available (try booting the demangler container and attaching it to the network)')
        self._sess = None
      yield self
    self._sess = None

  async def resolve(self, q: str) -> str:
    if self._sess:
      async with self._sess.get(f'{self._url}{q}') as resp:
        return (await resp.json())['to'] # type:ignore[no-any-return]
    else:
      return q

@cache
def _find_swift_demangler() -> Optional[str]:
  from subprocess import run, CalledProcessError
  try:
    if run('which swift-demangle', shell=True, capture_output=True).stdout:
      return 'swift-demangle'
    elif run('which swift', shell=True, capture_output=True).stdout:
      return 'swift demangle'
    else:
      return None
  except CalledProcessError:
    return None
