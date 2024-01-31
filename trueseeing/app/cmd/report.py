from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Optional
  from trueseeing.api import CommandHelper, Command, CommandMap

class ReportCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return ReportCommand(helper)

  def get_commands(self) -> CommandMap:
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

    self._helper.require_target()

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.report import HTMLReportGenerator
    context = self._helper.get_context()
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

    self._helper.require_target()

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.report import JSONReportGenerator
    context = self._helper.get_context()
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

    self._helper.require_target()

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.report import CIReportGenerator
    context = self._helper.get_context()
    gen = CIReportGenerator(context)
    if outfn is None:
      from io import StringIO
      f0 = StringIO()
      gen.generate(f0)
      ui.stdout(f0.getvalue())
    else:
      with open(outfn, 'w') as f1:
        gen.generate(f1)
