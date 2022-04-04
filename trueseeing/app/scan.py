# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <altakey@gmail.com>
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
from typing import TYPE_CHECKING

import asyncio
from pubsub import pub

from trueseeing.core.report import CIReportGenerator, JSONReportGenerator, HTMLReportGenerator
from trueseeing.core.context import Context
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Type, Optional, TextIO
  from trueseeing.core.report import ReportGenerator, ReportFormat
  from trueseeing.signature.base import Detector
  from trueseeing.core.issue import Issue

class ScanMode:
  _files: List[str]
  def __init__(self, files: List[str]) -> None:
    self._files = files

  async def invoke(self, ci_mode: ReportFormat, outfile: Optional[str], signatures: List[Type[Detector]], exclude_packages: List[str] = []) -> int:
    error_found = False
    session = AnalyzeSession(signatures, ci_mode=ci_mode, outfile=outfile, exclude_packages=exclude_packages)
    for f in self._files:
      if await session.invoke(f):
        error_found = True
    if not error_found:
      return 0
    else:
      return 1

class AnalyzeSession:
  _chain: List[Type[Detector]]
  _ci_mode: ReportFormat
  _outfile: Optional[str]
  _exclude_packages: List[str]
  def __init__(self, chain: List[Type[Detector]], outfile: Optional[str], ci_mode: ReportFormat = "html", exclude_packages: List[str] = []):
    self._ci_mode = ci_mode
    self._outfile = outfile
    self._chain = chain
    self._exclude_packages = exclude_packages

  async def invoke(self, apkfilename: str) -> bool:
    with Context(apkfilename, self._exclude_packages) as context:
      await context.analyze()
      ui.info(f"{apkfilename} -> {context.wd}")
      with context.store().db as db:
        db.execute('delete from analysis_issues')

      found = False

      reporter: ReportGenerator
      if self._outfile is None:
        reporter = CIReportGenerator(context)
      else:
        if self._ci_mode == 'json':
          reporter = JSONReportGenerator(context)
        else:
          reporter = HTMLReportGenerator(context)

      with context.store().db as db:
        # XXX
        def _detected(issue: Issue) -> None:
          global found
          found = True # type: ignore[name-defined]
          reporter.note(issue)
          db.execute(
            'insert into analysis_issues (detector, summary, synopsis, description, seealso, solution, info1, info2, info3, confidence, cvss3_score, cvss3_vector, source, row, col) values (:detector_id, :summary, :synopsis, :description, :seealso, :solution, :info1, :info2, :info3, :confidence, :cvss3_score, :cvss3_vector, :source, :row, :col)',
            issue.__dict__)
        pub.subscribe(_detected, 'issue')
        await asyncio.gather(*[c(context).detect() for c in self._chain])
        pub.unsubscribe(_detected, 'issue')

      if self._outfile is not None:
        with self._open_outfile() as f:
          reporter.generate(f)

      return reporter.return_(found)

  def _open_outfile(self) -> TextIO:
    assert self._outfile is not None
    if self._outfile == '-':
      import sys
      return sys.stdout
    else:
      return open(self._outfile, 'w')
