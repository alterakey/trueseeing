# -*- Coding: utf-8 -*-
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

import glob
import os
import re

from pubsub import pub

from trueseeing.core.code.model import InvocationPattern
from trueseeing.signature.base import Detector
from trueseeing.core.issue import Issue
from trueseeing.core.literalquery import Query

if TYPE_CHECKING:
  from typing import Iterable, Optional, List, Dict, Any, Set
  from trueseeing.core.code.model import Op

# XXX huge duplication
class TopLevelSuffixes:
  def __init__(self) -> None:
    import pkg_resources
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'tlds.txt')), 'r', encoding='utf-8') as f:
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
    import pkg_resources
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'public_suffix_list.dat')), 'r', encoding='utf-8') as f:
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
    package = self._context.parsed_manifest().getroot().xpath('/manifest/@package', namespaces=dict(android='http://schemas.android.com/apk/res/android'))[0]

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
      pub.sendMessage('issue', issue=Issue(
        detector_id=self.option,
        confidence='firm',
        cvss3_vector=self._cvss,
        summary='detected library',
        info1=f'{p} (score: {len(packages[p])})',
      ))

    for p in reversed(sorted(packages.keys(), key=len)):
      for k in self._context.store().query().consts_in_package(p, InvocationPattern('const-string', r'[0-9]+\.[0-9]+|(19|20)[0-9]{2}[ /-]')):
        ver = k.p[1].v
        if not re.search(r'^/|:[0-9]+|\\|://', ver):
          comps = ver.split('.')
          if len(comps) > 4:
            continue
          if ' and ' not in ver and re.match('^[0-9]|^v[0-9]', ver):
            if len(comps) < 4 or self._comp4_looks_like_version(comps):
              pub.sendMessage('issue', issue=Issue(
                detector_id=self.option,
                confidence='firm',
                cvss3_vector=self._cvss,
                summary='detected library version',
                info1=f'{ver} ({p})',
              ))
            else:
              pub.sendMessage('issue', issue=Issue(
                detector_id=self.option,
                confidence='tentative',
                cvss3_vector=self._cvss,
                summary='potential library version',
                info1=f'{ver} ({p})',
              ))
          else:
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='tentative',
              cvss3_vector=self._cvss,
              summary='potential version/dated reference in library',
              info1=f'{ver} ({p})',
            ))

    files = [fn for fn in glob.glob(os.path.join(self._context.wd, 'assets', '**/*.js'), recursive=True) if os.path.isfile(fn)]
    for fn in files:
      with open(fn, 'r', encoding='utf-8', errors='ignore') as f:
        for l in f:
          for m in re.finditer(r'[0-9]+\.[0-9]+|(19|20)[0-9]{2}[ /-]', l):
            ver = l
            if not re.search(r'^/|:[0-9]+|\\|://|[\x00-\x1f]', ver):
              pub.sendMessage('issue', issue=Issue(
                detector_id=self.option,
                confidence='tentative',
                cvss3_vector=self._cvss,
                summary='potential version/dated reference in library',
                info1='{match} ({rfn})'.format(rfn=os.path.relpath(fn, self._context.wd), match=ver),
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

  @classmethod
  def _class_name_of(self, path: str) -> str:
    return path.replace('.smali', '').replace('/', '.')

  async def detect(self) -> None:
    for c in (self._class_name_of(self._context.source_name_of_disassembled_class(r)) for r in self._context.disassembled_classes()):
      if re.search(r'(?:^|\.)a$', c):
        pub.sendMessage('issue', issue=Issue(detector_id=self.option, confidence='certain', cvss3_vector=self._cvss_true, summary='detected obfuscator', info1='ProGuard'))
        break
    else:
      pub.sendMessage('issue', issue=Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss_false, summary='lack of obfuscation'))

class UrlLikeDetector(Detector):
  option = 'detect-url'
  description = 'Detects URL-like strings'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  _re_tlds: Optional[re.Pattern[str]] = None

  def _analyzed(self, x: str) -> Iterable[Dict[str, Any]]:
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
        if len(components) == 4 and all(re.match(r'^\d+$', c) for c in components):
          yield dict(type_='possible IPv4 address', value=[hostlike])
        elif self._re_tlds.search(components[-1]):
          if not re.search(r'^android\.(intent|media)\.', hostlike):
            yield dict(type_='possible FQDN', value=[hostlike])

  async def detect(self) -> None:
    import pkg_resources
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'tlds.txt')), 'r', encoding='utf-8') as f:
      self._re_tlds = re.compile('^(?:{})$'.format('|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#'))), flags=re.IGNORECASE)

    with self._context.store() as store:
      for cl in store.query().consts(InvocationPattern('const-string', r'://|^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+|^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?$')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        for match in self._analyzed(cl.p[1].v):
          for v in match['value']:
            pub.sendMessage('issue', issue=Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss, summary=f'detected {match["type_"]}', info1=v, source=qn))
      for name, val in self._context.string_resources():
        for match in self._analyzed(val):
          for v in match['value']:
            pub.sendMessage('issue', issue=Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss, summary=f'detected {match["type_"]}', info1=v, source=f'R.string.{name}'))

class NativeMethodDetector(Detector):
  option = 'detect-native-method'
  description = 'Detects natively defined methods'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'Natively defined methods'
  _synopsis = "The application uses JNI."
  _detailed_description = None

  async def detect(self) -> None:
    with self._context.store() as store:
      for op in self._nativeish_methods(store.db):
        pub.sendMessage('issue', issue=Issue(
          detector_id=self.option,
          confidence='firm',
          cvss3_vector=self._cvss,
          summary=self._summary,
          synopsis=self._synopsis,
          source=store.query().qualname_of(op)
        ))

  def _nativeish_methods(self, c: Any) -> Iterable[Op]:
    for r in c.execute('select op_vecs.op as _0, t as _1, v as _2, op1 as _3, t1 as _4, v1 as _5, op2 as _6, t2 as _7, v2 as _8, op3 as _9, t3 as _10, v3 as _11, op4 as _12, t4 as _13, v4 as _14, op5 as _15, t5 as _16, v5 as _17, op6 as _18, t6 as _19, v6 as _20, op7 as _21, t7 as _22, v7 as _23, op8 as _24, t8 as _25, v8 as _26, op9 as _27, t9 as _28, v9 as _29 from ops_method join op_vecs on (method=ops_method.op and method=op_vecs.op) where v=:pat or v2=:pat or v3=:pat or v4=:pat or v5=:pat or v6=:pat or v7=:pat or v8=:pat or v9=:pat', dict(pat='native')):
      yield Query._op_from_row(r)

class NativeArchDetector(Detector):
  option = 'detect-native-arch'
  description = 'Detects supported architectures'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'Supported architectures'
  _synopsis = "The application has native codes for some architectures."

  async def detect(self) -> None:
    dirs = [fn for fn in glob.glob(os.path.join(self._context.wd, 'lib', '*')) if os.path.isdir(fn)]
    for d in dirs:
      if re.search(r'arm|x86|mips', d):
        pub.sendMessage('issue', issue=Issue(
          detector_id=self.option,
          confidence='firm',
          cvss3_vector=self._cvss,
          summary=self._summary,
          info1=os.path.basename(d),
          synopsis=self._synopsis,
        ))
