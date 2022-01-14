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

from trueseeing.core.issue import Issue
from trueseeing.core.cvss import CVSS3Scoring
from trueseeing.core.tools import noneif
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Protocol, Any, Dict
  from trueseeing.core.context import Context

  class Reporter(Protocol):
    def issue(self, issue: Issue) -> None: ...
    def progress(self) -> None: ...
    def done(self) -> None: ...

  class ReportGenerator(Protocol):
    def progress(self) -> Reporter: ...
    def note(self, issue: Issue) -> None: ...
    def generate(self) -> None: ...
    def return_(self, found: bool) -> bool: ...

class NullReporter:
  def __init__(self) -> None:
    pass

  def issue(self, issue: Issue) -> None:
    pass

  def progress(self) -> None:
    pass

  def done(self) -> None:
    pass

class ProgressReporter:
  def __init__(self, total_sigs: int) -> None:
    self._sigs_done = 0
    self._sigs_total = total_sigs
    self._issues = dict(critical=0, high=0, medium=0, low=0, info=0, progress=0.0)

  def issue(self, issue: Issue) -> None:
    self._issues[issue.severity()] += 1
    self._report()

  def progress(self) -> None:
    self._sigs_done += 1
    self._issues['progress'] = 100.0 * (self._sigs_done / float(self._sigs_total))
    self._report()

  def _report(self) -> None:
    ui.stderr('\ranalyzing: {progress:.01f}%: critical:{critical} high:{high} medium:{medium} low:{low} info:{info}'.format(**self._issues), nl=False)

  def done(self) -> None:
    ui.stderr('\n', nl=False)

class BaseReportGenerator:
  def __init__(self, context: Context, progress: Reporter):
    self._progress = progress
    self._context = context

  def progress(self) -> Reporter:
    return self._progress

  def note(self, issue: Issue) -> None:
    self._progress.issue(issue)

  def generate(self) -> None:
    self._progress.done()

  def return_(self, found: bool) -> bool:
    return found

class CIReportGenerator(BaseReportGenerator):
  def __init__(self, context: Context):
    super().__init__(context, NullReporter())

  def note(self, issue: Issue) -> None:
    super().note(issue)
    self._write(self._formatted(issue))

  def _write(self, x: str) -> None:
    ui.error(x)

  def _formatted(self, issue: Issue) -> str:
    return '{source}:{row}:{col}:{severity}{{{confidence}}}:{description} [-W{detector_id}]'.format(
      source=noneif(issue.source, '(global)'),
      row=noneif(issue.row, 0),
      col=noneif(issue.col, 0),
      severity=issue.severity(),
      confidence=issue.confidence,
      description=issue.brief_description(),
      detector_id=issue.detector_id
    )

class HTMLReportGenerator(BaseReportGenerator):
  def __init__(self, context: Context, progress: Reporter):
    super().__init__(context, progress)
    import os.path
    from jinja2 import Environment, FileSystemLoader
    from pkg_resources import resource_filename
    self._template = Environment(loader=FileSystemLoader(resource_filename(__name__, os.path.join('..', 'libs', 'template'))), autoescape=True).get_template('report.html')

  def generate(self) -> None:
    super().generate()
    with self._context.store().db as db:
      issues = []
      for no, row in enumerate(db.execute('select distinct detector, summary, synopsis, description, seealso, solution, cvss3_score, cvss3_vector from analysis_issues order by cvss3_score desc')):
        instances: List[Dict[str, Any]] = []
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

  def _write(self, x: str) -> None:
    ui.stdout(x, nl=False)

class JSONReportGenerator(BaseReportGenerator):
  def __init__(self, context: Context, progress: Reporter):
    super().__init__(context, progress)

  def generate(self) -> None:
    super().generate()
    from json import dumps
    with self._context.store().db as db:
      issues = []
      for no, row in enumerate(db.execute('select distinct detector, summary, synopsis, description, seealso, solution, cvss3_score, cvss3_vector from analysis_issues order by cvss3_score desc')):
        instances: List[Dict[str, Any]]= []
        issues.append(dict(
          no=no,
          detector=row[0],
          summary=row[1].title(),
          synopsis=row[2],
          description=row[3],
          seealso=row[4],
          solution=row[5],
          cvss3_score=row[6],
          cvss3_vector=row[7],
          severity=CVSS3Scoring.severity_of(row[6]).title(),
          instances=instances
          ))
        for m in db.execute('select * from analysis_issues where detector=:detector and summary=:summary and cvss3_score=:cvss3_score', {v:row[k] for k,v in {0:'detector', 1:'summary', 6:'cvss3_score'}.items()}):
          issue = Issue.from_analysis_issues_row(m)
          instances.append(dict(
            info=issue.brief_info(),
            source=issue.source,
            row=issue.row,
            col=issue.col))

      app = dict(
        package=self._context.parsed_manifest().getroot().xpath('/manifest/@package', namespaces=dict(android='http://schemas.android.com/apk/res/android'))[0],
        issues=len(issues)
      )
      self._write(dumps({"app": app, "issues": issues}, indent=2))

  def _write(self, x: str) -> None:
    ui.stdout(x, nl=False)
