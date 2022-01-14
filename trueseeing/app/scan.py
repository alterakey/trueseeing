# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
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

import sys

from trueseeing.core.report import CIReportGenerator, JSONReportGenerator, HTMLReportGenerator, ProgressReporter
from trueseeing.core.context import Context
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Type
  from trueseeing.core.report import ReportGenerator
  from trueseeing.signature.base import Detector

class ScanMode:
  _files: List[str]
  def __init__(self, files: List[str]) -> None:
    self._files = files

  def invoke(self, ci_mode: str, signatures: List[Type[Detector]]) -> int:
    error_found = False
    session = AnalyzeSession(signatures, ci_mode=ci_mode)
    for f in self._files:
      if session.invoke(f):
        error_found = True
    if not error_found:
      return 0
    else:
      return 1

class AnalyzeSession:
  _chain: List[Type[Detector]]
  _ci_mode: str
  def __init__(self, chain: List[Type[Detector]], ci_mode: str = "html"):
    self._ci_mode = ci_mode
    self._chain = chain

  def invoke(self, apkfilename: str) -> bool:
    with Context(apkfilename) as context:
      context.analyze()
      ui.info(f"{apkfilename} -> {context.wd}")
      with context.store().db as db:
        db.execute('delete from analysis_issues')

      found = False
      sigs_total = len(self._chain)

      reporter: ReportGenerator
      if self._ci_mode == 'gcc':
        reporter = CIReportGenerator(context)
      elif self._ci_mode == 'json':
        reporter = JSONReportGenerator(context, ProgressReporter(sigs_total))
      else:
        reporter = HTMLReportGenerator(context, ProgressReporter(sigs_total))

      for c in self._chain:
        with context.store().db as db:
          for e in c(context).detect():
            found = True
            reporter.note(e)
            db.execute(
              'insert into analysis_issues (detector, summary, synopsis, description, seealso, solution, info1, info2, info3, confidence, cvss3_score, cvss3_vector, source, row, col) values (:detector_id, :summary, :synopsis, :description, :seealso, :solution, :info1, :info2, :info3, :confidence, :cvss3_score, :cvss3_vector, :source, :row, :col)',
              e.__dict__)
          else:
            reporter.progress().progress()
      else:
        reporter.generate()
      return reporter.return_(found)
