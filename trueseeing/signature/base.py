import os
import re
import glob
import importlib
import pkg_resources
import math

class IssueSeverity:
  CRITICAL = 'critical'
  HIGH = 'high'
  MEDIUM = 'medium'
  LOW = 'low'
  INFO = 'info'

class IssueConfidence:
  CERTAIN = 'certain'
  FIRM = 'firm'
  TENTATIVE = 'tentative'

class Issue:
  @staticmethod
  def from_desc(detector_id, confidence, cvss3_vector, summary, info1, info2, info3, source, row=None, col=None):
    o = Issue()
    cvss3_vector = '%sRC:%s/' % (cvss3_vector, {IssueConfidence.CERTAIN:'C',IssueConfidence.FIRM:'R',IssueConfidence.TENTATIVE:'U'}[confidence])
    o.detector_id = detector_id
    o.confidence = confidence
    o.cvss3_vector = cvss3_vector
    o.source = source
    o.summary = summary
    o.info1 = info1
    o.info2 = info2
    o.info3 = info3
    o.row = row
    o.col = col
    o.cvss3_score = o.cvss3_score_from(cvss3_vector)
    return o

  @staticmethod
  def from_analysis_issues_row(row):
    o = Issue()
    o.detector_id, o.summary, \
    o.info1, o.info2, o.info3, o.confidence, \
    o.cvss3_score, o.cvss3_vector, o.source, o.row, \
    o.col = row
    return o

  def severity(self):
    if self.cvss3_score <= 0.0:
      return IssueSeverity.INFO
    elif self.cvss3_score < 4.0:
      return IssueSeverity.LOW
    elif self.cvss3_score < 7.0:
      return IssueSeverity.MEDIUM
    elif self.cvss3_score < 9.0:
      return IssueSeverity.HIGH
    else:
      return IssueSeverity.CRITICAL

  def description(self):
    return ': '.join(filter(None, (self.summary, self.info1, self.info2, self.info3)))

  def cvss3_score_from(self, vec):
    m = re.match(r'CVSS:3.0/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/S:(?P<S>[CU])/C:(?P<C>[HLN])/I:(?P<I>[HLN])/A:(?P<A>[HLN])(?:/RC:(?P<RC>[XCRU]))?/', vec)
    if m:
      def score(m):
        return temporal_score(m)

      def temporal_score(m):
        return roundup(base_score(m) * exploit_code_maturity_score(m) * remediation_level_score(m) * report_confidence_score(m))

      def exploit_code_maturity_score(m):
        return 1

      def remediation_level_score(m):
        return 1

      def report_confidence_score(m):
        M = dict(X=1.0, C=1.0, R=0.96, U=0.92)
        return M[m.group('RC')]

      def base_score(m):
        impact, exploitability = subscore_impact(m), subscore_exploitability(m)
        if impact <= 0:
          return 0
        else:
          if not scope_changed(m):
            return roundup(min(impact + exploitability, 10))
          else:
            return roundup(min(1.08 * (impact + exploitability), 10))

      def subscore_impact(m):
        base = subscore_impact_base(m)
        if not scope_changed(m):
          return 6.42 * base
        else:
          return 7.52*(base-0.029) - 3.25*(base-0.02)**15

      def subscore_impact_base(m):
        M = dict(N=0, L=0.22, H=0.56)
        C, I, A = M[m.group('C')], M[m.group('I')], M[m.group('A')]
        return 1 - ((1-C) * (1-I) * (1-A))

      def subscore_exploitability(m):
        M_AV = dict(N=0.85, A=0.62, L=0.55, P=0.2)
        M_AC = dict(L=0.77, H=0.44)
        M_PR = dict(N=0.85, L=0.68 if scope_changed(m) else 0.62, H=0.50 if scope_changed(m) else 0.27)
        M_UI = dict(N=0.85, R=0.62)
        AV, AC, PR, UI = M_AV[m.group('AV')], M_AC[m.group('AC')], M_PR[m.group('PR')], M_UI[m.group('UI')]

        return 8.22 * AV * AC * PR * UI

      def scope_changed(m):
        return (m.group('S') == 'C')

      def roundup(v):
        return math.ceil(v * 10.0) / 10.0

      return score(m)
    else:
      raise ValueError()

class Detector:
  option = None

  def __init__(self, context):
    self.context = context

  @classmethod
  def as_signature(cls):
    return (cls.option, cls)

  def detect(self):
    res = self.do_detect()
    if res is not None:
      yield from res
    else:
      yield from []

  def do_detect(self):
    pass

  def issue(self, *args, **kwargs):
    return Issue.from_desc(self.option, *args, **kwargs)

class SignatureDiscoverer:
  PRIORITY = ['fingerprint', 'manifest', 'security']

  def __init__(self):
    pass

  def discovered(self):
    return sorted([os.path.basename(r).replace('.py', '') for r in glob.glob(pkg_resources.resource_filename(__name__, os.path.join('*'))) if re.match(r'^[^_].*\.py$', os.path.basename(r)) and not re.match('^base.py$', os.path.basename(r))], key=self.key)

  def key(self, k):
    try:
      return self.PRIORITY.index(k)
    except ValueError:
      return 31337

class SignatureClasses:
  def __init__(self):
    pass

  def extracted(self):
    mods = [importlib.import_module('trueseeing.signature.%s' % s) for s in SignatureDiscoverer().discovered()]
    for m in mods:
      for attr in dir(m):
        i = getattr(m, attr)
        try:
          if issubclass(i, Detector) and i.option:
            yield i
        except TypeError:
          pass
