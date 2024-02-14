from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from trueseeing.api import Command, CommandHelper, CommandMap

class AnalyzeCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return AnalyzeCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'a':dict(e=self._analyze, n='a[a][!]', d='analyze target (aa: full analysis)'),
      'a!':dict(e=self._analyze),
      'aa':dict(e=self._analyze2),
      'aa!':dict(e=self._analyze2),
    }

  async def _analyze(self, args: deque[str], level: int = 2) -> None:
    target = self._helper.require_target()

    cmd = args.popleft()

    ui.info(f"analyzing {target}")

    context = self._helper.get_context()
    if cmd.endswith('!'):
      context.remove()
    await context.analyze(level=level)

  async def _analyze2(self, args: deque[str]) -> None:
    await self._analyze(args, level=3)
