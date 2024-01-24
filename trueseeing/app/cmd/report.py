from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.api import Command
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Dict, Optional
  from trueseeing.app.inspect import Runner, CommandEntry

class ReportCommand(Command):
  _runner: Runner

  def __init__(self, runner: Runner) -> None:
    self._runner = runner

  def get_commands(self) -> Dict[str, CommandEntry]:
    return {
      'gh':dict(e=self._report_html, n='gh[!] [report.html]', d='generate report (HTML)'),
      'gh!':dict(e=self._report_html),
      'gj':dict(e=self._report_json, n='gj[!] [report.json]', d='generate report (JSON)'),
      'gj!':dict(e=self._report_json),
      'gt':dict(e=self._report_text, n='gt[!] [report.txt]', d='generate report (text)'),
      'gt!':dict(e=self._report_text),
    }

  async def _report_html(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._runner._require_target()
    assert self._runner._target is not None

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.report import HTMLReportGenerator
    context = self._runner._get_context(self._runner._target)
    gen = HTMLReportGenerator(context)
    if outfn is None:
      from io import StringIO
      f0 = StringIO()
      gen.generate(f0)
      ui.stdout(f0.getvalue())
    else:
      with open(outfn, 'w') as f1:
        gen.generate(f1)

  async def _report_json(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._runner._require_target()
    assert self._runner._target is not None

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.report import JSONReportGenerator
    context = self._runner._get_context(self._runner._target)
    gen = JSONReportGenerator(context)
    if outfn is None:
      from io import StringIO
      f0 = StringIO()
      gen.generate(f0)
      ui.stdout(f0.getvalue())
    else:
      with open(outfn, 'w') as f1:
        gen.generate(f1)

  async def _report_text(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._runner._require_target()
    assert self._runner._target is not None

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.report import CIReportGenerator
    context = self._runner._get_context(self._runner._target)
    gen = CIReportGenerator(context)
    if outfn is None:
      from io import StringIO
      f0 = StringIO()
      gen.generate(f0)
      ui.stdout(f0.getvalue())
    else:
      with open(outfn, 'w') as f1:
        gen.generate(f1)
