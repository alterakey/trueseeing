from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.core.report import CIReportGenerator, JSONReportGenerator, HTMLReportGenerator
from trueseeing.core.context import Context
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Type, Optional, TextIO
  from trueseeing.core.report import ReportGenerator, ReportFormat
  from trueseeing.core.model.sig import Detector

class ScanMode:
  _files: List[str]
  _ci_mode: ReportFormat
  _outfile: Optional[str] = None
  _sigs: List[Type[Detector]]
  _exclude_packages: List[str] = []
  _update_cache_mode: bool = False
  _no_cache_mode: bool = False
  _from_inspect_mode: bool = False
  _keep_current_issues: bool = False

  def __init__(self, files: List[str], ci_mode: ReportFormat, outfile: Optional[str], signatures: List[Type[Detector]], exclude_packages: List[str] = [], update_cache_mode: bool = False, no_cache_mode: bool = False, from_inspect_mode: bool = False, keep_current_issues: bool = False) -> None:
    self._files = files
    self._ci_mode = ci_mode
    self._outfile = outfile
    self._sigs = signatures
    self._exclude_packages = exclude_packages
    self._update_cache_mode = update_cache_mode
    self._no_cache_mode = no_cache_mode
    self._from_inspect_mode = from_inspect_mode
    self._keep_current_issues = keep_current_issues

  async def invoke(self) -> int:
    if self._update_cache_mode:
      for f in self._files:
        await self._do_update_cache(f)
      return 0
    else:
      import time
      error_found = False
      for f in self._files:
        at = time.time()
        try:
          nr = await self._do_scan(f)
          if nr:
            error_found = True
          if not self._from_inspect_mode:
            ui.success('{fn}: analysis done, {nr} issues ({t:.02f} sec.)'.format(fn=f, nr=nr, t=(time.time() - at)))
        finally:
          if self._no_cache_mode:
            Context(f, []).remove()

      if not error_found:
        return 0
      else:
        return 1

  async def _do_update_cache(self, path: str) -> None:
    ctx = Context(path, [])
    ctx.remove()
    await ctx.analyze()

  async def _do_scan(self, path: str) -> int:
    from trueseeing.core.scan import Scanner

    context = Context(path, self._exclude_packages)
    reporter = self._get_reporter(context)
    scanner = Scanner(context, reporter=reporter, sigs=self._sigs, excludes=self._exclude_packages)

    await context.analyze()
    ui.info(f"{path} -> {context.wd}")

    with context.store().query().scoped() as q:
      if not self._keep_current_issues:
        await scanner.clear(q)
      nr = await scanner.scan(q)

    if self._outfile is not None:
      with self._open_outfile() as f:
        reporter.generate(f)

    reporter.return_(True if nr else False)
    return nr

  def _open_outfile(self) -> TextIO:
    assert self._outfile is not None
    if self._outfile == '-':
      import sys
      return sys.stdout
    else:
      return open(self._outfile, 'w')

  def _get_reporter(self, context: Context) -> ReportGenerator:
    if self._outfile is None:
      return CIReportGenerator(context)
    else:
      if self._ci_mode == 'json':
        return JSONReportGenerator(context)
      else:
        return HTMLReportGenerator(context)
