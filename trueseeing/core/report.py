from __future__ import annotations
from typing import TYPE_CHECKING

import os

from trueseeing.core.cvss import CVSS3Scoring
from trueseeing.core.tools import noneif
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Protocol, Any, Dict, TextIO, Set
  from typing_extensions import Literal
  from trueseeing.core.context import Context
  from trueseeing.core.model.issue import Issue

  ReportFormat = Literal['html', 'json']

  class ReportGenerator(Protocol):
    def __init__(self, context: Context) -> None: ...
    def generate(self, f: TextIO) -> None: ...

class ConsoleNoter:
  _seen: Set[Issue]

  def __init__(self) -> None:
    self._seen = set()

  def note(self, issue: Issue) -> None:
    if issue not in self._seen:
      ui.info(self._formatted(issue))
      self._seen.add(issue)

  @classmethod
  def _formatted(cls, issue: Issue) -> str:
    return '{aff0}:{aff1}:{aff2}:{sev}{{{cfd}}}:{desc} [{sigid}]'.format(
      aff0=noneif(issue.aff0, '(global)'),
      aff1=noneif(issue.aff1, 0),
      aff2=noneif(issue.aff2, 0),
      sev=issue.sev,
      cfd=issue.cfd,
      desc=issue.brief_desc(),
      sigid=issue.sigid
    )

class CIReportGenerator:
  def __init__(self, context: Context) -> None:
    self._context = context

  def generate(self, f: TextIO) -> None:
    for issue in self._context.store().query().issues():
      f.write(ConsoleNoter._formatted(issue) + '\n')

class HTMLReportGenerator:
  def __init__(self, context: Context) -> None:
    from trueseeing import __version__
    self._context = context
    self._toolchain = dict(version=__version__)

  def generate(self, f: TextIO) -> None:
    with self._context.store().db as db:
      from datetime import datetime
      from zoneinfo import ZoneInfo

      from trueseeing.core.android.db import Query
      query = Query(c=db)
      app: Dict[str, Any] = dict(
        path=self._context.target,
      )
      issues = []

      ts = datetime.now(tz=ZoneInfo('UTC')).isoformat(timespec='seconds')

      if self._context.type == 'apk':
        ctx = self._context.require_type('apk')
        apk = ctx.target
        manif = ctx.parsed_manifest()
        ns = dict(android='http://schemas.android.com/apk/res/android')

        app.update(dict(
          package=manif.xpath('/manifest/@package', namespaces=ns)[0],
          version_name=manif.xpath('/manifest/@android:versionName', namespaces=ns)[0],
          version_code=manif.xpath('/manifest/@android:versionCode', namespaces=ns)[0],
          size=os.stat(apk).st_size,
        ))

      for no, row in query.findings_list():
        instances: List[Dict[str, Any]] = []
        issues.append(dict(no=no, sig=row[0], title=row[1].title(), summary=row[2], desc=row[3], ref=row[4], sol=row[5], score=row[6], cvss=row[7], sev=CVSS3Scoring.severity_of(row[6]).title(), insts=instances, severity_panel_style={'critical':'panel-danger', 'high':'panel-warning', 'medium':'panel-warning', 'low':'panel-success', 'info':'panel-info'}[CVSS3Scoring.severity_of(row[6])]))
        for issue in query.issues_by_group(sig=row[0], title=row[1]):
          instances.append(dict(info=issue.brief_info(), aff0=issue.aff0, aff1=issue.aff1, aff2=issue.aff2))

      app.update(dict(
        fp=self._context.fingerprint_of(),
        issues=len(issues),
        issues_critical=len([_ for _ in issues if _['sev'] == 'Critical']),
        issues_high=len([_ for _ in issues if _['sev'] == 'High']),
        issues_medium=len([_ for _ in issues if _['sev'] == 'Medium']),
        issues_low=len([_ for _ in issues if _['sev'] == 'Low']),
        issues_info=len([_ for _ in issues if _['sev'] == 'Info']),
      ))

      from importlib.resources import as_file, files
      from jinja2 import Environment, FileSystemLoader
      with as_file(files('trueseeing')/'libs'/'template') as path:
        env = Environment(loader=FileSystemLoader(path), autoescape=True, trim_blocks=True, lstrip_blocks=True)
        env.filters['excerpt'] = self._excerpt
        f.write(env.get_template('report.html').render(app=app, issues=issues, toolchain=self._toolchain, ts=ts))

  @staticmethod
  def _excerpt(x: str, w: int = 256, p: float = 0.214, ellipsis: str = ' ... ') -> str:
    l = len(x)
    if l < w:
      return x
    else:
      pl1 = int(w * p)
      pl0 = w - pl1 - len(ellipsis)
      return x[:pl0] + ellipsis + x[-pl1:]

class JSONReportGenerator:
  def __init__(self, context: Context) -> None:
    self._context = context

  def generate(self, f: TextIO) -> None:
    from json import dumps
    with self._context.store().db as db:
      from trueseeing.core.android.db import Query
      query = Query(c=db)
      issues = []
      app: Dict[str, Any] = dict(
        path=self._context.target,
      )

      if self._context.type == 'apk':
        ctx = self._context.require_type('apk')
        apk = ctx.target
        manif = ctx.parsed_manifest()
        ns = dict(android='http://schemas.android.com/apk/res/android')

        app.update(dict(
          package=manif.xpath('/manifest/@package', namespaces=ns)[0],
          version_name=manif.xpath('/manifest/@android:versionName', namespaces=ns)[0],
          version_code=manif.xpath('/manifest/@android:versionCode', namespaces=ns)[0],
          size=os.stat(apk).st_size,
        ))

      for no, row in query.findings_list():
        instances: List[Dict[str, Any]] = []
        issues.append(dict(
          no=no,
          sig=row[0],
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
        for issue in query.issues_by_group(sig=row[0], title=row[1]):
          instances.append(dict(
            info=issue.brief_info(),
            source=issue.aff0,
            row=issue.aff1,
            col=issue.aff2))

      app.update(dict(
        fp=self._context.fingerprint_of(),
        issues=len(issues)
      ))
      f.write(dumps({"app": app, "issues": issues}, indent=2))
