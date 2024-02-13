from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.core.ui import CoreProgressReporter, ScanProgressReporter, ui
from trueseeing.core.context import FileOpener

if TYPE_CHECKING:
  from typing import List, Optional
  from trueseeing.core.context import Context
  from trueseeing.core.report import ReportGenerator, ReportFormat
  from trueseeing.core.scan import Scanner

class ScanMode:
  _target: str
  _outfile: Optional[str] = None
  _context: Context
  _reporter: ReportGenerator
  _scanner: Scanner
  _opener: FileOpener

  def __init__(self, target: str, outform: ReportFormat, outfile: Optional[str], sigsels: List[str] = [], excludes: List[str] = []) -> None:
    from trueseeing.core.scan import Scanner
    self._target = target
    self._outfile = outfile
    self._context = FileOpener().get_context(self._target)
    self._context.excludes = excludes
    self._reporter = self._get_reporter(self._context, outform, outfile)
    self._scanner = Scanner(self._context, sigsels=sigsels, excludes=excludes)

  async def reanalyze(self) -> int:
    with CoreProgressReporter().scoped():
      self._context.remove()
      await self._context.analyze()
      return 0

  async def scan(self, incremental: bool = False, oneshot: bool = False) -> int:
    from trueseeing.core.exc import InvalidSchemaError
    with CoreProgressReporter().scoped():
      import time
      at = time.time()
      try:
        try:
          await self._context.analyze()
        except InvalidSchemaError:
          ui.warn('invalid schema detected; forcing reanalysis')
          self._context.remove()
          await self._context.analyze()

        ui.info(f"{self._target} -> {self._context.wd}")

        with self._context.store().query().scoped() as q:
          if not incremental:
            await self._scanner.clear(q)

          with ScanProgressReporter().scoped():
            nr = await self._scanner.scan(q)

        if self._outfile is not None:
          if self._outfile == '-':
            from sys import stdout
            self._reporter.generate(stdout)
          else:
            with open(self._outfile, 'w') as f:
              self._reporter.generate(f)

        ui.success('{fn}: analysis done, {nr} issues ({t:.02f} sec.)'.format(fn=self._target, nr=nr, t=(time.time() - at)))

        return 1 if nr else 0
      finally:
        if oneshot:
          self._context.remove()

  @classmethod
  def _get_reporter(cls, context: Context, format: ReportFormat, fn: Optional[str]) -> ReportGenerator:
    from trueseeing.core.report import CIReportGenerator, JSONReportGenerator, HTMLReportGenerator
    if fn is None:
      return CIReportGenerator(context)
    else:
      if format == 'json':
        return JSONReportGenerator(context)
      else:
        return HTMLReportGenerator(context)
