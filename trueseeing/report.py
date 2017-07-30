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

import os
import sys
import logging
import jinja2
import json

from trueseeing.issue import Issue
from trueseeing.cvss import CVSS3Scoring
from trueseeing.tools import noneif

log = logging.getLogger(__name__)

class NullReporter:
  def __init__(self):
    pass

  def issue(self, issue):
    pass

  def progress(self):
    pass

  def done(self):
    pass

class ProgressReporter:
  def __init__(self, total_sigs):
    self._sigs_done = 0
    self._sigs_total = total_sigs
    self._issues = dict(critical=0, high=0, medium=0, low=0, info=0, progress=0.0)

  def issue(self, issue):
    self._issues[issue.severity()] += 1
    self._report()

  def progress(self):
    self._sigs_done += 1
    self._issues['progress'] = 100.0 * (self._sigs_done / float(self._sigs_total))
    self._report()

  def _report(self):
    sys.stderr.write('\ranalyzing: %(progress).01f%%: critical:%(critical)d high:%(high)d medium:%(medium)d low:%(low)d info:%(info)d' % self._issues)
    sys.stderr.flush()

  def done(self):
    sys.stderr.write('\n')
    sys.stderr.flush()

class ReportGenerator:
  def __init__(self, context, progress):
    self._progress = progress
    self._context = context

  def progress(self):
    return self._progress

  def note(self, issue):
    self._progress.issue(issue)

  def generate(self):
    self._progress.done()

  def return_(self, found):
    return found

class CIReportGenerator(ReportGenerator):
  def __init__(self, context):
    super().__init__(context, NullReporter())

  def note(self, issue):
    super().note(issue)
    self._write(self._formatted(issue))

  def _write(self, x):
    log.error(x)

  def _formatted(self, issue):
    return '%(source)s:%(row)d:%(col)d:%(severity)s{%(confidence)s}:%(description)s [-W%(detector_id)s]' % dict(source=noneif(issue.source, '(global)'), row=noneif(issue.row, 0), col=noneif(issue.col, 0), severity=issue.severity(), confidence=issue.confidence, description=issue.brief_description(), detector_id=issue.detector_id)

class HTMLReportGenerator(ReportGenerator):
  def __init__(self, context, progress):
    super().__init__(context, progress)
    self._template = jinja2.Environment(loader=jinja2.PackageLoader('trueseeing', 'template'), autoescape=True).get_template('report.html')

  def generate(self):
    super().generate()
    with self._context.store().db as db:
      issues = []
      for row, no in zip(db.execute('select distinct detector, summary, synopsis, description, seealso, solution, cvss3_score, cvss3_vector from analysis_issues order by cvss3_score desc'), range(1, 2**32)):
        instances = []
        issues.append(dict(no=no, detector=row[0], summary=row[1].title(), synopsis=row[2], description=row[3], seealso=row[4], solution=row[5], cvss3_score=row[6], cvss3_vector=row[7], severity=CVSS3Scoring.severity_of(row[6]).title(), instances=instances, severity_panel_style={'critical':'panel-danger', 'high':'panel-warning', 'medium':'panel-warning', 'low':'panel-success', 'info':'panel-info'}[CVSS3Scoring.severity_of(row[6])]))
        for m in db.execute('select * from analysis_issues where detector=:detector and summary=:summary and cvss3_score=:cvss3_score', {v:row[k] for k,v in {0:'detector', 1:'summary', 6:'cvss3_score'}.items()}):
          issue = Issue.from_analysis_issues_row(m)
          instances.append(dict(info=issue.brief_info(), source=issue.source, row=issue.row, col=issue.col))

      app = dict(
        package=self._context.parsed_manifest().getroot().xpath('/manifest/@package', namespaces=dict(android='http://schemas.android.com/apk/res/android'))[0],
        issues=len(issues),
        issues_critical=len([_ for _ in issues if _['severity'] == 'Critical']),
        issues_high=len([_ for _ in issues if _['severity'] == 'High']),
        issues_medium=len([_ for _ in issues if _['severity'] == 'Medium']),
        issues_low=len([_ for _ in issues if _['severity'] == 'Low']),
        issues_info=len([_ for _ in issues if _['severity'] == 'Info'])
      )
      self._write(self._template.render(app=app, issues=issues))

  def _write(self, x):
    sys.stdout.write(x)
    sys.stdout.flush()
