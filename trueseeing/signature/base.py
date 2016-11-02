import os
import re
import glob
import importlib
import pkg_resources

class IssueSeverity:
  SEVERE = 'severe'
  MAJOR = 'major'
  MEDIUM = 'medium'
  MINOR = 'minor'
  INFO = 'info'

class IssueConfidence:
  CERTAIN = 'certain'
  FIRM = 'firm'
  TENTATIVE = 'tentative'

class Issue:
  def __init__(self, detector_id, severity, confidence, source, description, row=None, col=None):
    self.detector_id = detector_id
    self.severity = severity
    self.confidence = confidence
    self.source = source
    self.description = description
    self.row = row
    self.col = col

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
    return Issue(self.option, *args, **kwargs)

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
