# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
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

import logging
import sys

from trueseeing.core.report import CIReportGenerator, HTMLReportGenerator, ProgressReporter
from trueseeing.core.context import Context

log = logging.getLogger(__name__)

class ScanMode:
  def __init__(self, files):
    self._files = files

  def invoke(self, ci_mode, signatures):
    if self._files:
      error_found = False
      session = AnalyzeSession(signatures, ci_mode=ci_mode)
      for f in self._files:
        if session.invoke(f):
          error_found = True
      if not error_found:
        return 0
      else:
        return 1
    else:
      print("%s: no input files" % sys.argv[0])
      return 2

class AnalyzeSession:
  def __init__(self, chain, ci_mode=False):
    self._ci_mode = ci_mode
    self._chain = chain

  def invoke(self, apkfilename):
    with Context() as context:
      context.analyze(apkfilename)
      log.info("%s -> %s" % (apkfilename, context.wd))
      with context.store().db as db:
        db.execute('delete from analysis_issues')

      found = False
      sigs_total = len(self._chain)

      if self._ci_mode:
        reporter = CIReportGenerator(context)
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

