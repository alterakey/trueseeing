import os
import sys
import logging
import jinja2

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

  def done(self):
    sys.stderr.write('\n')

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

class CIReportGenerator(ReportGenerator):
  def __init__(self, context):
    super().__init__(context, NullReporter())

  def note(self, issue):
    super().note(issue)
    log.error(self._formatted(issue))

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
      for row, no in zip(db.execute('select distinct detector, summary, cvss3_score, cvss3_vector from analysis_issues order by cvss3_score desc'), range(1, 2**32)):
        instances = []
        issues.append(dict(no=no, detector=row[0], summary=row[1].title(), cvss3_score=row[2], cvss3_vector=row[3], severity=CVSS3Scoring.severity_of(row[2]).title(), instances=instances))
        for m in db.execute('select * from analysis_issues where detector=:detector and summary=:summary and cvss3_score=:cvss3_score', {v:row[k] for k,v in {0:'detector', 1:'summary', 2:'cvss3_score'}.items()}):
          issue = Issue.from_analysis_issues_row(m)
          instances.append(dict(info=issue.brief_info(), source=issue.source, row=issue.row, col=issue.col))
      sys.stdout.write(self._template.render(issues=issues))
