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

from trueseeing.core.report import CIReportGenerator, JSONReportGenerator, HTMLReportGenerator
from trueseeing.core.context import Context
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Type, Optional, TextIO
  from trueseeing.core.report import ReportGenerator, ReportFormat
  from trueseeing.signature.base import Detector

class ScanMode:
  _files: List[str]
  def __init__(self, files: List[str]) -> None:
    self._files = files

  def invoke(self, ci_mode: ReportFormat, outfile: Optional[str], signatures: List[Type[Detector]], exclude_packages: List[str] = []) -> int:
    error_found = False
    session = AnalyzeSession(signatures, ci_mode=ci_mode, outfile=outfile, exclude_packages=exclude_packages)
    for f in self._files:
      if session.invoke(f):
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

  def invoke(self, apkfilename: str) -> bool:
    with Context(apkfilename, self._exclude_packages) as context:
      context.analyze()
      ui.info(f"{apkfilename} -> {context.wd}")
      with context.store().db as db:
        db.execute('delete from analysis_issues')

      found = False

      reporter: ReportGenerator
      if self._ci_mode == 'gcc':
        reporter = CIReportGenerator(context)
      elif self._ci_mode == 'json':
        reporter = JSONReportGenerator(context)
      else:
        reporter = HTMLReportGenerator(context)

      for c in self._chain:
        with context.store().db as db:
          for e in c(context).detect():
            found = True
            reporter.note(e)
            db.execute(
              'insert into analysis_issues (detector, summary, synopsis, description, seealso, solution, info1, info2, info3, confidence, cvss3_score, cvss3_vector, source, row, col) values (:detector_id, :summary, :synopsis, :description, :seealso, :solution, :info1, :info2, :info3, :confidence, :cvss3_score, :cvss3_vector, :source, :row, :col)',
              e.__dict__)
      else:
        with self._open_outfile() as f:
          reporter.generate(f)
      return reporter.return_(found)

  def _open_outfile(self) -> TextIO:
    if self._outfile is None:
      import sys
      return sys.stdout
    else:
      return open(self._outfile, 'w')
