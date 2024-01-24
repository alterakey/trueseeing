from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.api import Command
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Dict, List, Type
  from trueseeing.app.inspect import Runner, CommandEntry, ModifierEntry
  from trueseeing.signature.base import Detector

class ScanCommand(Command):
  _runner: Runner

  def __init__(self, runner: Runner) -> None:
    self._runner = runner

  def get_commands(self) -> Dict[str, CommandEntry]:
    return {
      '?s?':dict(e=self._help_signature, n='?s?', d='signature help'),
      'as':dict(e=self._scan, n='as[!]', d='run a scan (!: clear current issues)'),
      'as!':dict(e=self._scan),
    }

  def get_modifiers(self) -> Dict[str, ModifierEntry]:
    return {
      's':dict(n='@s:sig', d='include sig'),
      'x':dict(n='@x:pa.ckage.name', d='exclude package'),
    }

  async def _help_signature(self, args: deque[str]) -> None:
    ui.success('Signatures:')
    sigs = self._runner._sigs.content
    width = 2 + max([len(k) for k in sigs.keys()])
    for k in sorted(sigs.keys()):
      ui.stderr(
        f'{{n:<{width}s}}{{d}}'.format(n=k, d=sigs[k].description)
      )

  async def _scan(self, args: deque[str]) -> None:
    self._runner._require_target()
    assert self._runner._target is not None

    cmd = args.popleft()
    apk = self._runner._target

    limit = self._runner._get_graph_size_limit(self._runner._get_modifiers(args))

    import time
    from trueseeing.app.scan import ScanMode

    with self._runner._apply_graph_size_limit(limit):
      at = time.time()

      if cmd.endswith('!'):
        ui.info('clearing current issues')

      await ScanMode([apk]).invoke(
        ci_mode='html',
        outfile=None,
        signatures=self._get_effective_sigs(self._runner._get_modifiers(args)),
        exclude_packages=[],
        no_cache_mode=False,
        update_cache_mode=False,
        from_inspect_mode=True,
        keep_current_issues=(not cmd.endswith('!')),
      )
      nr = self._runner._get_context(apk).store().query().issue_count()
      ui.success("done, found {nr} issues ({t:.02f} sec.)".format(nr=nr, t=(time.time() - at)))

  def _get_effective_sigs(self, mods: List[str]) -> List[Type[Detector]]:
    signature_selected = self._runner._sigs.default().copy()
    for m in mods:
      if m.startswith('@s:'):
        for a in m[3:].split(','):
          if a.startswith('no-'):
            signature_selected.difference_update(self._runner._sigs.selected_on(a[3:]))
          else:
            signature_selected.update(self._runner._sigs.selected_on(a))
    return [v for k, v in self._runner._sigs.content.items() if k in signature_selected]
