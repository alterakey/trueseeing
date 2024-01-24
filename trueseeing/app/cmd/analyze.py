from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.api import Command
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Dict
  from trueseeing.app.inspect import Runner, CommandEntry

class AnalyzeCommand(Command):
  _runner: Runner

  def __init__(self, runner: Runner) -> None:
    self._runner = runner

  def get_commands(self) -> Dict[str, CommandEntry]:
    return {
      'a':dict(e=self._analyze, n='a[a][!]', d='analyze target (aa: full analysis)'),
      'a!':dict(e=self._analyze),
      'aa':dict(e=self._analyze2),
      'aa!':dict(e=self._analyze2),
    }

  async def _analyze(self, args: deque[str], level: int = 2) -> None:
    self._runner._require_target()
    assert self._runner._target is not None

    cmd = args.popleft()
    apk = self._runner._target

    ui.info(f"analyzing {apk}")

    context = self._runner._get_context(apk)
    if cmd.endswith('!'):
      context.remove()
    await context.analyze(level=level)

  async def _analyze2(self, args: deque[str]) -> None:
    await self._analyze(args, level=3)
