from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List
  from trueseeing.api import CommandHelper, Command, CommandMap, ModifierMap

class ScanCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return ScanCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      '?s?':dict(e=self._help_signature, n='?s?', d='signature help'),
      'as':dict(e=self._scan, n='as[!]', d='run a scan (!: clear current issues)'),
      'as!':dict(e=self._scan),
    }

  def get_modifiers(self) -> ModifierMap:
    return {
      's':dict(n='@s:sig', d='include sig'),
      'x':dict(n='@x:pa.ckage.name', d='exclude package'),
    }

  async def _help_signature(self, args: deque[str]) -> None:
    from trueseeing.core.scan import Scanner
    ui.success('Signatures:')
    sigs = Scanner.get_all_signatures()
    width = 2 + max([len(k) for k in sigs.keys()])
    for k in sorted(sigs.keys()):
      ui.stderr(
        f'{{n:<{width}s}}{{d}}'.format(n=k, d=sigs[k]['d'])
      )

  async def _scan(self, args: deque[str]) -> None:
    import time
    from trueseeing.core.scan import Scanner
    from trueseeing.core.ui import ScanProgressReporter

    self._helper.require_target()

    cmd = args.popleft()

    context = await self._helper.get_context_analyzed(level=3)
    limit = self._helper.get_graph_size_limit(self._helper.get_modifiers(args))
    sigsels = self._get_sigsels(self._helper.get_modifiers(args))
    scanner = Scanner(context, sigsels=sigsels, max_graph_size=limit)

    at = time.time()
    with context.store().query().scoped() as q:
      if cmd.endswith('!'):
        ui.info('clearing current issues')
        await scanner.clear(q)

      with ScanProgressReporter().scoped():
        nr = await scanner.scan(q)

      ui.success("done, found {nr} issues ({t:.02f} sec.)".format(nr=nr, t=(time.time() - at)))

  def _get_sigsels(self, mods: List[str]) -> List[str]:
    for m in mods:
      if m.startswith('@s:'):
        return m[3:].split(',')
    return []
