from __future__ import annotations
from typing import TYPE_CHECKING
import io
import os
import re

from trueseeing.core.model.sig import SignatureMixin
from trueseeing.core.android.model.code import InvocationPattern
from trueseeing.core.android.analysis.flow import DataFlow

if TYPE_CHECKING:
  from typing import Iterable, Optional, List, Dict, Any, Set
  from trueseeing.api import Signature, SignatureHelper, SignatureMap
  from trueseeing.core.model.issue import IssueConfidence

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

class LibraryDetector(SignatureMixin):
  _id = 'detect-library'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  _suffixes_top: TopLevelSuffixes = TopLevelSuffixes()
  _suffixes_public: PublicSuffixes = PublicSuffixes()

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return LibraryDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id: dict(e=self.detect, d='Detects libraries')}

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
    context = self._helper.get_context('apk')
    q = context.store().query()
    package = context.parsed_manifest().xpath('/manifest/@package', namespaces=dict(android='http://schemas.android.com/apk/res/android'))[0]

    packages: Dict[str, List[str]] = dict()
    for fn in (context.source_name_of_disassembled_class(r) for r in context.disassembled_classes()):
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
      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cvss=self._cvss,
        title='detected library',
        info0=f'{p} (score: {len(packages[p])})',
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
              self._helper.raise_issue(self._helper.build_issue(
                sigid=self._id,
                cvss=self._cvss,
                title='detected library version',
                info0=f'{ver} ({p})',
              ))
            else:
              self._helper.raise_issue(self._helper.build_issue(
                sigid=self._id,
                cfd='tentative',
                cvss=self._cvss,
                title='potential library version',
                info0=f'{ver} ({p})',
              ))
          else:
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cfd='tentative',
              cvss=self._cvss,
              title='potential version/dated reference in library',
              info0=f'{ver} ({p})',
            ))

    for fn, blob in q.file_enum('root/assets/%.js'):
      f = io.StringIO(blob.decode('utf-8', errors='ignore'))
      for l in f:
        for m in re.finditer(r'[0-9]+\.[0-9]+|(19|20)[0-9]{2}[ /-]', l):
          ver = l
          if not re.search(r'^/|:[0-9]+|\\|://|[\x00-\x1f]', ver):
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cfd='tentative',
              cvss=self._cvss,
              title='potential version/dated reference in library',
              info0='{match} ({rfn})'.format(rfn=fn, match=ver),
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

class ProGuardDetector(SignatureMixin):
  _id = 'detect-obfuscator'
  _cvss_true = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss_false = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/'

  _whitelist = ['R']

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ProGuardDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects obfuscators')}

  @classmethod
  def _class_name_of(self, path: str) -> str:
    return path.replace('.smali', '').replace('/', '.')

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    for c in (self._class_name_of(context.source_name_of_disassembled_class(r)) for r in context.disassembled_classes()):
      m = re.search(r'(?:^|\.)(.)$', c)
      if m and m.group(1) not in self._whitelist:
        self._helper.raise_issue(self._helper.build_issue(sigid=self._id, cfd='certain', cvss=self._cvss_true, title='detected obfuscator', info0='ProGuard'))
        break
    else:
      self._helper.raise_issue(self._helper.build_issue(sigid=self._id, cvss=self._cvss_false, title='lack of obfuscation'))

class UrlLikeDetector(SignatureMixin):
  _id = 'detect-url'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  _re_tlds: Optional[re.Pattern[str]] = None

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return UrlLikeDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {'detect-url':dict(e=self.detect, d='Detects URL-like strings')}

  def _analyzed(self, x: str, qn: Optional[str] = None) -> Iterable[Dict[str, Any]]:
    assert self._re_tlds is not None
    if '://' in x:
      yield dict(type_='URL', value=re.findall(r'\S+://\S+', x), cfd='firm')
    elif re.search(r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+', x):
      yield dict(type_='path component', value=re.findall(r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+', x), cfd='firm')
    elif re.search(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?$', x):
      m = re.search(r'^([^:/]+)', x)
      if m:
        hostlike = m.group(1)
        components = hostlike.split('.')
        if len(components) == 4 and all(re.match(r'^\d+$', c) for c in components) and all(int(c) < 256 for c in components):
          if re.match(r'1\.[239]\.|2\.(1|5|160)\.|3\.1\.', hostlike) and qn is not None and re.search(r'asn1|ASN1|x509|X509|KeyUsage', qn):
            pass
          else:
            yield dict(type_='possible IPv4 address', value=[hostlike], cfd='firm')
        elif self._re_tlds.search(components[-1]):
          if not re.search(r'^android\.(intent|media)\.|^os\.name$|^java\.vm\.name|^[A-Z]+.*\.(java|EC|name|secure)$|^Dispatchers\.IO', hostlike):
            confidence: IssueConfidence = 'firm'
            if re.search(r'^(java|os|kotlin|google\.[a-z]+?)\.|^(com|cn)\.google|\.(date|time|host|help|prof|name|top|link|id|icu|app|[a-z]{5,})$', hostlike, flags=re.IGNORECASE):
              confidence = 'tentative'
            yield dict(type_='possible FQDN', value=[hostlike], cfd=confidence)

  async def detect(self) -> None:
    from importlib.resources import files
    with (files('trueseeing')/'libs'/'tlds.txt').open('r', encoding='utf-8') as f:
      self._re_tlds = re.compile('^(?:{})$'.format('|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#'))), flags=re.IGNORECASE)

    context = self._helper.get_context('apk')
    q = context.store().query()
    for cl in q.consts(InvocationPattern('const-string', r'://|^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+|^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?$')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      for match in self._analyzed(cl.p[1].v, qn):
        for v in match['value']:
          self._helper.raise_issue(self._helper.build_issue(sigid=self._id, cfd=match['cfd'], cvss=self._cvss, title=f'detected {match["type_"]}', info0=v, aff0=qn))
    for name, val in context.string_resources():
      for match in self._analyzed(val):
        for v in match['value']:
          self._helper.raise_issue(self._helper.build_issue(sigid=self._id, cfd=match['cfd'], cvss=self._cvss, title=f'detected {match["type_"]}', info0=v, aff0=f'R.string.{name}'))

class NativeMethodDetector(SignatureMixin):
  _id = 'detect-native-method'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'Natively defined methods'
  _synopsis = "The application uses JNI."
  _detailed_description = None

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return NativeMethodDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects natively defined methods')}

  async def detect(self) -> None:
    context = self._helper.get_context()
    store = context.store()
    q = store.query()
    for op in q.methods_with_modifier('native'):
      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cvss=self._cvss,
        title=self._summary,
        summary=self._synopsis,
        aff0=q.qualname_of(op)
      ))

class NativeArchDetector(SignatureMixin):
  _id = 'detect-native-arch'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'Supported architectures'
  _synopsis = "The application has native codes for some architectures."

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return NativeArchDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects supported architectures')}

  async def detect(self) -> None:
    for d in self._helper.get_context().store().query().file_find('root/lib/%'):
      if re.search(r'arm|x86|mips', d):
        arch = d.split('/')[2]
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cvss=self._cvss,
          title=self._summary,
          info0=arch,
          info1=os.path.basename(d),
          summary=self._synopsis,
        ))

class ReflectionDetector(SignatureMixin):
  _id = 'detect-reflection'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary0 = 'Use of reflection'
  _synopsis0 = "The application makes use of Java reflection APIs."
  _summary1 = 'Classloader reference'
  _synopsis1 = "The application makes use of classloaders."

  _blacklist_caller = [
    r'Lkotlin/',
    r'Lkotlinx/',
  ]

  _blacklist_meth = [
    r'Ljava/lang/Object;->getClass\(\)',
    r'Ljava/lang/Class;->getClassLoader',
    r'Ljava/lang/Class;->get((Simple|Canonical)?Name|ComponentType|Annotation)',
    r'Ljava/lang/Class;->.*?\(\)',
    r'Ljava/lang/reflect/Method;->.*?\(\)',
    r'Ljava/lang/reflect/Field;->.*?\(\)',
  ]

  _blacklist_val = [
    r'^-?0x[0-9a-f]+$'
  ]

  _masker = '(unknown)'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ReflectionDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects reflections')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.invocations(InvocationPattern('invoke-', '^Ljavax?.*/(Class|Method|Field);->|^Ljava/lang/[A-Za-z]*?ClassLoader;->')):
      qn = q.qualname_of(cl)
      if qn:
        if context.is_qualname_excluded(qn):
          continue
        if any(re.match(x, qn) for x in self._blacklist_caller):
          continue
      ct = q.method_call_target_of(cl)
      if ct is None:
        continue
      if any(re.match(x, ct) for x in self._blacklist_meth):
        continue
      if 'ClassLoader;->' in ct:
        try:
          xs = DataFlow(q).solved_possible_constant_data_in_invocation(cl, 0)
          if not xs:
            xs = {self._masker}
          for x in xs:
            if any(re.match(p, x) for p in self._blacklist_val):
              x = self._masker
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cvss=self._cvss,
              title=self._summary1,
              info0=ct,
              info1=x,
              aff0=qn,
              summary=self._synopsis1,
              desc=self._synopsis1,
            ))
        except IndexError:
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cvss=self._cvss,
            title=self._summary1,
            info0=ct,
            aff0=qn,
            summary=self._synopsis1,
            desc=self._synopsis1,
          ))
      else:
        try:
          xs = DataFlow(q).solved_possible_constant_data_in_invocation(cl, 0)
          if not xs:
            xs = {self._masker}
          for x in xs:
            if any(re.match(p, x) for p in self._blacklist_val):
              x = self._masker
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cvss=self._cvss,
              title=self._summary0,
              info0=ct,
              info1=x,
              aff0=qn,
              summary=self._synopsis0,
              desc=self._synopsis0,
            ))
        except IndexError:
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cvss=self._cvss,
            title=self._summary0,
            info0=ct,
            aff0=qn,
            summary=self._synopsis0,
            desc=self._synopsis0,
          ))
