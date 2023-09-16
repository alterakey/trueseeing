# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-23 Takahiro Yoshimura <altakey@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations
from collections import deque
import asyncio
import shlex
import sys
from typing import TYPE_CHECKING

from trueseeing.core.ui import ui
from trueseeing.core.exc import FatalError

if TYPE_CHECKING:
  from typing import Mapping, Optional, Any, NoReturn
  from trueseeing.app.shell import Signatures

class InspectMode:
  def do(
      self,
      target: str,
      signatures: Signatures
  ) -> NoReturn:
    from code import InteractiveConsole

    sein = self
    runner = Runner(target)

    asyncio.run(runner.greeting())

    class LambdaConsole(InteractiveConsole):
      def runsource(self, source: str, filename: Optional[str]=None, symbol: Optional[str]=None) -> bool:
        try:
          asyncio.run(sein._worker(runner.run(source)))
        except FatalError:
          pass
        return False

    try:
      import readline
    except ImportError:
      readline = None # type: ignore[assignment] # noqa: F841
    ps1, ps2 = getattr(sys, 'ps1', None), getattr(sys, 'ps2', None)
    try:
      sys.ps1, sys.ps2 = 'ts> ', '... '
      LambdaConsole(locals=locals(), filename='<input>').interact(banner='', exitmsg='')
      sys.exit(0)
    finally:
      sys.ps1, sys.ps2 = ps1, ps2

  async def _worker(self, coro: Any) -> None:
    tasks = [asyncio.create_task(coro)]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
      t.cancel()
    if pending:
      _, _ = await asyncio.wait(pending)
    for t in done:
      if not t.cancelled():
        x = t.exception()
        if x and not isinstance(x, FatalError):
          assert isinstance(x, Exception)
          ui.fatal('unhandled exception', exc=x)

class Runner:
  _cmds: Mapping[str, Mapping[str, Any]]
  _quiet: bool = False
  _verbose: bool = False
  _target: str

  def __init__(self, target: str) -> None:
    self._target = target
    self._cmds = {
      '?':dict(e=self._help, n='?', d='help'),
      '?s':dict(e=self._help_signature, n='?s', d='signature help'),
      'a':dict(e=self._analyze, n='a', d='analyze target'),
    }

  async def greeting(self) -> None:
    from trueseeing import __version__ as version
    ui.success(f"Trueseeing {version} [inspect mode]")

  async def run(self, s: str) -> None:
    try:
      tokens = deque(shlex.split(s))
      if not tokens:
        return

      c = tokens[0]
      if c not in self._cmds:
        ui.error('invalid command, type ? for help')
      else:
        try:
          ent: Any = self._cmds[c]['e']
          await ent(tokens)
        except FatalError:
          pass
    finally:
      self._reset_loglevel()

  def _reset_loglevel(self, debug:bool = False) -> None:
    ui.set_level(ui.INFO)

  async def _help(self, args: deque[str]) -> None:
    ui.success('Commands:')
    width = (2 + max([len(e.get('d', '')) for e in self._cmds.values()]) // 4) * 4
    for c, e in self._cmds.items():
      if 'n' in e:
        ui.info(
          f'{{n:<{width}s}}{{d}}'.format(n=e['n'], d=e['d'])
        )
        
  async def _help_signature(self, args: deque[str]) -> None:
    ui.success('Signatures:')
    width = (2 + max([len(e.get('d', '')) for e in self._cmds.values()]) // 4) * 4
    for c, e in self._cmds.items():
      if 'n' in e:
        ui.info(
          f'{{n:<{width}s}}{{d}}'.format(n=e['n'], d=e['d'])
        )

  async def _analyze(self, args: deque[str]) -> None:
    from trueseeing.core.context import Context
    with Context(self._target, []) as context:
      await context.analyze()
      ui.info(f"{self._target} -> {context.wd}")
      with context.store().db as db:
        db.execute('delete from analysis_issues')
