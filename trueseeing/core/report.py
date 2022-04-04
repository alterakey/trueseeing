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

from trueseeing.core.issue import Issue
from trueseeing.core.cvss import CVSS3Scoring
from trueseeing.core.tools import noneif
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Protocol, Any, Dict, TextIO
  from typing_extensions import Literal
  from trueseeing.core.context import Context

  ReportFormat = Literal['html', 'json']

  class ReportGenerator(Protocol):
    def note(self, issue: Issue) -> None: ...
    def generate(self, f: TextIO) -> None: ...
    def return_(self, found: bool) -> bool: ...

class CIReportGenerator:
  def __init__(self, context: Context):
    self._context = context

  def note(self, issue: Issue) -> None:
    ui.info(self.formatted(issue))

  def generate(self, f: TextIO) -> None:
    pass

  def return_(self, found: bool) -> bool:
    return found

  @classmethod
  def formatted(cls, issue: Issue) -> str:
    return '{source}:{row}:{col}:{severity}{{{confidence}}}:{description} [-W{detector_id}]'.format(
      source=noneif(issue.source, '(global)'),
      row=noneif(issue.row, 0),
      col=noneif(issue.col, 0),
      severity=issue.severity(),
      confidence=issue.confidence,
      description=issue.brief_description(),
      detector_id=issue.detector_id
    )

class HTMLReportGenerator(CIReportGenerator):
  def __init__(self, context: Context):
    super().__init__(context)
    import os.path
    from jinja2 import Environment, FileSystemLoader
    from pkg_resources import resource_filename
    from trueseeing import __version__
    self._template = Environment(loader=FileSystemLoader(resource_filename(__name__, os.path.join('..', 'libs', 'template'))), autoescape=True).get_template('report.html')
    self._toolchain = dict(version=__version__)

  def generate(self, f: TextIO) -> None:
    super().generate(f)
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
      f.write(self._template.render(app=app, issues=issues, toolchain=self._toolchain))

class JSONReportGenerator(CIReportGenerator):
  def generate(self, f: TextIO) -> None:
    from json import dumps
    with self._context.store().db as db:
      issues = []
      for no, row in enumerate(db.execute('select distinct detector, summary, synopsis, description, seealso, solution, cvss3_score, cvss3_vector from analysis_issues order by cvss3_score desc')):
        instances: List[Dict[str, Any]] = []
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
      f.write(dumps({"app": app, "issues": issues}, indent=2))
