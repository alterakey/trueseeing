from __future__ import annotations
from typing import TYPE_CHECKING

import io
import os
import re

from trueseeing.core.model.code import InvocationPattern
from trueseeing.core.analysis.flow import DataFlows
from trueseeing.core.model.sig import Detector
from trueseeing.core.model.issue import Issue

if TYPE_CHECKING:
  from typing import Iterable, Optional, List, Dict, Any, Set

# XXX huge duplication
class TopLevelSuffixes:
  def __init__(self) -> None:
    from importlib.resources import files
    with (files('trueseeing')/'libs'/'tlds.txt').open('r', encoding='utf-8') as f:
      self._re_tlds = re.compile('^(?:{})$'.format('|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#'))), flags=re.IGNORECASE)

  def looks_public(self, names: List[str]) -> bool:
    if names:
      gtld = names[0]
      return (gtld == 'android') or bool(self._re_tlds.search(gtld))
    else:
      return False

class PublicSuffixes:
  _suffixes: Set[str] = set()

  def __init__(self) -> None:
    from importlib.resources import files
    with (files('trueseeing')/'libs'/'public_suffix_list.dat').open('r', encoding='utf-8') as f:
      self._suffixes.update((l for l in f if l and not l.startswith('//')))

  def looks_public(self, names: List[str]) -> bool:
    suf = '.'.join(reversed(names))
    return suf in self._suffixes

class LibraryDetector(Detector):
  option = 'detect-library'
  description = 'Detects libraries'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  _suffixes_top: TopLevelSuffixes = TopLevelSuffixes()
  _suffixes_public: PublicSuffixes = PublicSuffixes()

  @classmethod
  def _package_name_of(cls, path: str) -> str:
    return os.path.dirname(path).replace('/', '.')

  @classmethod
  def _package_family_of(cls, p: str) -> Optional[str]:
    f = {
      r'javax\..*': None,
      r'(android\.support\.v[0-9]+)\..*': r'\1',
      r'(com\.google\.android\.gms)\..*': r'\1',
      r'(.*?)\.internal(?:\..*)?$': r'\1',
      r'(.*?)(?:\.[a-z]{,4})+$': r'\1',
      r'([a-z0-9_]{5,}(?:\.[a-z0-9_]{2,})+?)\..*': r'\1',
    }
    for k, v in f.items():
      if re.match(k, p):
        if v is not None:
          return re.sub(k, v, p)
        else:
          return None

    return p

  @classmethod
  def _shared_package_of(cls, c1: str, c2: str) -> Optional[List[str]]:
    o = []
    try:
      for a,b in zip(c1.split('.'), c2.split('.')):
        if a == b:
          o.append(a)
        else:
          break
    finally:
      return o

  @classmethod
  def _is_kind_of(cls, c1: str, c2: str) -> bool:
    shared = cls._shared_package_of(c1, c2)
    if shared is None:
      return False
    elif not len(shared):
      return False
    elif len(shared) == 1:
      return not cls._suffixes_top.looks_public(shared)
    elif len(shared) > 2:
      return True
    else:
      return not cls._suffixes_public.looks_public(shared)

  async def detect(self) -> None:
    q = self._context.store().query()
    package = self._context.parsed_manifest().xpath('/manifest/@package', namespaces=dict(android='http://schemas.android.com/apk/res/android'))[0]

    packages: Dict[str, List[str]] = dict()
    for fn in (self._context.source_name_of_disassembled_class(r) for r in self._context.disassembled_classes()):
      # XXX exclude packages
      family = self._package_family_of(self._package_name_of(fn))
      if family is not None:
        try:
          packages[family].append(fn)
        except KeyError:
          packages[family] = [fn]
        else:
          pass
    packages = {k:v for k,v in packages.items() if not self._is_kind_of(k, package) and re.search(r'\.[a-zA-Z0-9]{4,}(?:\.|$)', k)}

    for p in sorted(packages.keys()):
      self._raise_issue(Issue(
        detector_id=self.option,
        confidence='firm',
        cvss3_vector=self._cvss,
        summary='detected library',
        info1=f'{p} (score: {len(packages[p])})',
      ))

    for p in reversed(sorted(packages.keys(), key=len)):
      for k in q.consts_in_package(p, InvocationPattern('const-string', r'[0-9]+\.[0-9]+|(19|20)[0-9]{2}[ /-]')):
        ver = k.p[1].v
        if not re.search(r'^/|:[0-9]+|\\|://', ver):
          comps = ver.split('.')
          if len(comps) > 4:
            continue
          if ' and ' not in ver and re.match('^[0-9]|^v[0-9]', ver):
            if len(comps) < 4 or self._comp4_looks_like_version(comps):
              self._raise_issue(Issue(
                detector_id=self.option,
                confidence='firm',
                cvss3_vector=self._cvss,
                summary='detected library version',
                info1=f'{ver} ({p})',
              ))
            else:
              self._raise_issue(Issue(
                detector_id=self.option,
                confidence='tentative',
                cvss3_vector=self._cvss,
                summary='potential library version',
                info1=f'{ver} ({p})',
              ))
          else:
            self._raise_issue(Issue(
              detector_id=self.option,
              confidence='tentative',
              cvss3_vector=self._cvss,
              summary='potential version/dated reference in library',
              info1=f'{ver} ({p})',
            ))

    for fn, blob in q.file_enum('root/assets/%.js'):
      f = io.StringIO(blob.decode('utf-8', errors='ignore'))
      for l in f:
        for m in re.finditer(r'[0-9]+\.[0-9]+|(19|20)[0-9]{2}[ /-]', l):
          ver = l
          if not re.search(r'^/|:[0-9]+|\\|://|[\x00-\x1f]', ver):
            self._raise_issue(Issue(
              detector_id=self.option,
              confidence='tentative',
              cvss3_vector=self._cvss,
              summary='potential version/dated reference in library',
              info1='{match} ({rfn})'.format(rfn=fn, match=ver),
            ))

  def _comp4_looks_like_version(self, xs: List[str]) -> bool:
    if xs[0].lower().startswith('v'):
      return True
    ints = []
    for c in xs:
      try:
        ints.append(int(c))
      except ValueError:
        return True
    if 0 in ints or any([(t > 255) for t in ints]):
      return True
    elif all([(t < 100) for t in ints[:2]]):
      return True
    else:
      return False

class ProGuardDetector(Detector):
  option = 'detect-obfuscator'
  description = 'Detects obfuscators'
  _cvss_true = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss_false = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/'

  _whitelist = ['R']

  @classmethod
  def _class_name_of(self, path: str) -> str:
    return path.replace('.smali', '').replace('/', '.')

  async def detect(self) -> None:
    for c in (self._class_name_of(self._context.source_name_of_disassembled_class(r)) for r in self._context.disassembled_classes()):
      m = re.search(r'(?:^|\.)(.)$', c)
      if m and m.group(1) not in self._whitelist:
        self._raise_issue(Issue(detector_id=self.option, confidence='certain', cvss3_vector=self._cvss_true, summary='detected obfuscator', info1='ProGuard'))
        break
    else:
      self._raise_issue(Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss_false, summary='lack of obfuscation'))

class UrlLikeDetector(Detector):
  option = 'detect-url'
  description = 'Detects URL-like strings'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  _re_tlds: Optional[re.Pattern[str]] = None

  def _analyzed(self, x: str, qn: Optional[str] = None) -> Iterable[Dict[str, Any]]:
    assert self._re_tlds is not None
    if '://' in x:
      yield dict(type_='URL', value=re.findall(r'\S+://\S+', x))
    elif re.search(r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+', x):
      yield dict(type_='path component', value=re.findall(r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+', x))
    elif re.search(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?$', x):
      m = re.search(r'^([^:/]+)', x)
      if m:
        hostlike = m.group(1)
        components = hostlike.split('.')
        if len(components) == 4 and all(re.match(r'^\d+$', c) for c in components) and all(int(c) < 256 for c in components):
          if re.match(r'1\.[239]\.|2\.(1|5|160)\.|3\.1\.', hostlike) and qn is not None and re.search(r'asn1|x509|X509|KeyUsage', qn):
            pass
          else:
            yield dict(type_='possible IPv4 address', value=[hostlike])
        elif self._re_tlds.search(components[-1]):
          if not re.search(r'^android\.(intent|media)\.|^os\.name$|^java\.vm\.name|^[A-Z]+.*\.(java|EC|name|secure)$', hostlike):
            yield dict(type_='possible FQDN', value=[hostlike])

  async def detect(self) -> None:
    from importlib.resources import files
    with (files('trueseeing')/'libs'/'tlds.txt').open('r', encoding='utf-8') as f:
      self._re_tlds = re.compile('^(?:{})$'.format('|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#'))), flags=re.IGNORECASE)

    q = self._context.store().query()
    for cl in q.consts(InvocationPattern('const-string', r'://|^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+|^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?$')):
      qn = q.qualname_of(cl)
      if self._context.is_qualname_excluded(qn):
        continue
      for match in self._analyzed(cl.p[1].v, qn):
        for v in match['value']:
          self._raise_issue(Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss, summary=f'detected {match["type_"]}', info1=v, source=qn))
    for name, val in self._context.string_resources():
      for match in self._analyzed(val):
        for v in match['value']:
          self._raise_issue(Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss, summary=f'detected {match["type_"]}', info1=v, source=f'R.string.{name}'))

class NativeMethodDetector(Detector):
  option = 'detect-native-method'
  description = 'Detects natively defined methods'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'Natively defined methods'
  _synopsis = "The application uses JNI."
  _detailed_description = None

  async def detect(self) -> None:
    store = self._context.store()
    q = store.query()
    for op in q.methods_with_modifier('native'):
      self._raise_issue(Issue(
        detector_id=self.option,
        confidence='firm',
        cvss3_vector=self._cvss,
        summary=self._summary,
        synopsis=self._synopsis,
        source=q.qualname_of(op)
      ))

class NativeArchDetector(Detector):
  option = 'detect-native-arch'
  description = 'Detects supported architectures'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'Supported architectures'
  _synopsis = "The application has native codes for some architectures."

  async def detect(self) -> None:
    for d in self._context.store().query().file_find('root/lib/%'):
      if re.search(r'arm|x86|mips', d):
        arch = d.split('/')[2]
        self._raise_issue(Issue(
          detector_id=self.option,
          confidence='firm',
          cvss3_vector=self._cvss,
          summary=self._summary,
          info1=arch,
          info2=os.path.basename(d),
          synopsis=self._synopsis,
        ))

class ReflectionDetector(Detector):
  option = 'detect-reflection'
  description = 'Detects reflections'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary0 = 'Use of reflection'
  _synopsis0 = "The application makes use of Java reflection APIs."
  _summary1 = 'Classloader reference'
  _synopsis1 = "The application makes use of classloaders."

  _blacklist = [
    r'Ljava/lang/Object;->getClass\(\)',
    r'Ljava/lang/Class;->getClassLoader',
    r'Ljava/lang/Class;->get((Simple)?Name|ComponentType)',
    r'Ljava/lang/Class;->is(Instance|Array|Primitive)',
  ]

  async def detect(self) -> None:
    store = self._context.store()
    q = store.query()
    for cl in q.invocations(InvocationPattern('invoke-', '^Ljavax?.*/(Class|Method|Field);->|^Ljava/lang/[A-Za-z]*?ClassLoader;->')):
      qn = q.qualname_of(cl)
      if self._context.is_qualname_excluded(qn):
        continue
      ct = q.method_call_target_of(cl)
      if ct is None:
        continue
      if any(re.match(x, ct) for x in self._blacklist):
        continue
      if 'ClassLoader;->' in ct:
        try:
          for x in DataFlows.solved_possible_constant_data_in_invocation(store, cl, 0):
            self._raise_issue(Issue(
              detector_id=self.option,
              cvss3_vector=self._cvss,
              confidence='firm',
              summary=self._summary1,
              info1=ct,
              info2=x,
              source=qn,
              synopsis=self._synopsis1,
              description=self._synopsis1,
            ))
        except IndexError:
          self._raise_issue(Issue(
            detector_id=self.option,
            cvss3_vector=self._cvss,
            confidence='firm',
            summary=self._summary1,
            info1=ct,
            source=qn,
            synopsis=self._synopsis1,
            description=self._synopsis1,
          ))
      else:
        try:
          for x in DataFlows.solved_possible_constant_data_in_invocation(store, cl, 0):
            self._raise_issue(Issue(
              detector_id=self.option,
              cvss3_vector=self._cvss,
              confidence='firm',
              summary=self._summary0,
              info1=ct,
              info2=x,
              source=qn,
              synopsis=self._synopsis0,
              description=self._synopsis0,
            ))
        except IndexError:
          self._raise_issue(Issue(
            detector_id=self.option,
            cvss3_vector=self._cvss,
            confidence='firm',
            summary=self._summary0,
            info1=ct,
            source=qn,
            synopsis=self._synopsis0,
            description=self._synopsis0,
          ))
