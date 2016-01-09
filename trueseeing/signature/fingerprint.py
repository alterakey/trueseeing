# Vulnerabilities:
# * Fingerprinting libraries
# * Fingerprinting obfuscators

import collections
import itertools
import os
import re
from trueseeing.context import warning_on
from trueseeing.flow.code import OpMatcher, InvocationPattern
from trueseeing.flow.data import DataFlows

import pkg_resources

class Detector:
  def __init__(self, context):
    self.context = context
  def detect(self):
    pass

class LibraryDetector(Detector):
  def package_name_of(self, path):
    return os.path.dirname(path).replace('/', '.')

  def package_family_of(self, p):
    f = collections.OrderedDict([
      (r'javax\..*', None),
      (r'(android\.support\.v[0-9]+)\..*', r'\1'),
      (r'(com\.google\.android\.gms)\..*', r'\1'),
      (r'(.*?)\.internal(?:\..*)?$', r'\1'),
      (r'(.*?)(?:\.[a-z]{,4})+$', r'\1'),
      (r'([a-z0-9_]{5,}(?:\.[a-z0-9_]{2,})+?)\..*', r'\1'),
    ])
    for k, v in f.items():
      if re.match(k, p):
        try:
          return re.sub(k, v, p)
        except TypeError:
          return None
    else:
      return p
    
  def shared_package_of(self, c1, c2):
    o = []
    try:
      for a,b in zip(c1.split('.'), c2.split('.')):
        if a == b:
          o.append(a)
        else:
          break
    finally:
      return o

  def is_kind_of(self, c1, c2):
    return True if self.shared_package_of(c1, c2) else False

  def detect(self):
    package = self.context.parsed_manifest().getroot().xpath('/manifest/@package', namespaces=dict(android='http://schemas.android.com/apk/res/android'))[0]

    packages = dict()
    for fn in (self.context.source_name_of_disassembled_class(r) for r in self.context.disassembled_classes()):
      family = self.package_family_of(self.package_name_of(fn))
      if family is not None:
        try:
          packages[family].append(fn)
        except KeyError:
          packages[family] = [fn]
        else:
          pass
    packages = {k:v for k,v in packages.items() if not self.is_kind_of(k, package) and re.search(r'\.[a-zA-Z0-9]{4,}(?:\.|$)', k)}

    return [warning_on(name=self.context.apk, row=1, col=0, desc='detected library: %s (score: %d)' % (p, len(packages[p])), opt='-Wdetect-library') for p in sorted(packages.keys())]
  
class ProGuardDetector(Detector):
  def class_name_of(self, path):
    return path.replace('.smali', '').replace('/', '.')

  def detect(self):
    for c in (self.class_name_of(self.context.source_name_of_disassembled_class(r)) for r in self.context.disassembled_classes()):
      if re.search('(?:^|\.)a$', c):
        return [warning_on(name=self.context.apk, row=1, col=0, desc='detected obfuscator: ProGuard', opt='-Wdetect-obfuscator')]
    else:
      return []

class FakeToken:
  def __init__(self, v, p):
    self.v = v
    self.p = p

class UrlLikeDetector(Detector):
  def __init__(self, context):
    super().__init__(context)
    self.re_tlds = None
  
  def analyzed(self, x):
    if '://' in x:
      yield dict(type_='URL', value=re.findall(r'\S+://\S+', x))
    elif re.search(r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+', x):
      yield dict(type_='path component', value=re.findall(r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+', x))
    elif re.search(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?$', x):
      hostlike = re.search(r'^([^:/]+)', x).group(1)
      components = hostlike.split('.')
      if len(components) == 4 and all(re.match(r'^\d+$', c) for c in components):
        yield dict(type_='possible IPv4 address', value=[hostlike])
      elif self.re_tlds.search(components[-1]):
        yield dict(type_='possible FQDN', value=[hostlike])
        
  def detect(self):
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'tlds.txt')), 'r') as f:
      self.re_tlds = re.compile('^(?:%s)$' % '|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#')), flags=re.IGNORECASE)

    marks = []
    for cl in self.context.analyzed_classes():
      for k in OpMatcher(cl.ops, InvocationPattern('const-string', '.')).matching():
        for match in self.analyzed(k.p[1].v):
          for v in match['value']:
            marks.append(dict(name=self.context.class_name_of_dalvik_class_type(cl.qualified_name()), method=k.method_, op=k, target_val=v, target_type=match['type_']))
    for name, val in self.context.string_resources():
      for match in self.analyzed(val):
        for v in match['value']:
          marks.append(dict(name='resource', method=FakeToken(FakeToken('R.string.%s' % name, []), []), target_val=v, target_type=match['type_']))

    return [warning_on(name=m['name'] + '#' + m['method'].v.v, row=0, col=0, desc='detected %s: %s' % (m['target_type'], m['target_val']), opt='-Wdetect-url') for m in marks]
  
def detect_library(context):
  return LibraryDetector(context).detect()

def detect_obfuscators(context):
  return detect_obfuscator_proguard(context)

def detect_obfuscator_proguard(context):
  return ProGuardDetector(context).detect()
  
def detect_urllike(context):
  return UrlLikeDetector(context).detect()
