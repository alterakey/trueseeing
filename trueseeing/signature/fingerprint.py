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

# Issues:
# * Fingerprinting libraries
# * Fingerprinting obfuscators

from __future__ import annotations
from typing import TYPE_CHECKING

import os
import re
from trueseeing.core.code.model import InvocationPattern
from trueseeing.signature.base import Detector
from trueseeing.core.issue import Issue

if TYPE_CHECKING:
  from typing import Iterable, Optional, List, Dict, Any
  from trueseeing.core.context import Context

class LibraryDetector(Detector):
  option = 'detect-library'
  description = 'Detects libraries'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

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
    else:
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
    return True if cls._shared_package_of(c1, c2) else False

  def detect(self) -> Iterable[Issue]:
    package = self._context.parsed_manifest().getroot().xpath('/manifest/@package', namespaces=dict(android='http://schemas.android.com/apk/res/android'))[0]

    packages: Dict[str, List[str]] = dict()
    for fn in (self._context.source_name_of_disassembled_class(r) for r in self._context.disassembled_classes()):
      family = self._package_family_of(self._package_name_of(fn))
      if family is not None:
        try:
          packages[family].append(fn)
        except KeyError:
          packages[family] = [fn]
        else:
          pass
    packages = {k:v for k,v in packages.items() if not self._is_kind_of(k, package) and re.search(r'\.[a-zA-Z0-9]{4,}(?:\.|$)', k)}

    yield from (
      Issue(
        detector_id=self.option,
        confidence='firm',
        cvss3_vector=self._cvss,
        summary='detected library',
        info1=f'{p} (score: {len(packages[p])})',
      ) for p in sorted(packages.keys())
    )


class ProGuardDetector(Detector):
  option = 'detect-obfuscator'
  description = 'Detects obfuscators'
  _cvss_true = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss_false = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/'

  @classmethod
  def _class_name_of(self, path: str) -> str:
    return path.replace('.smali', '').replace('/', '.')

  def detect(self) -> Iterable[Issue]:
    for c in (self._class_name_of(self._context.source_name_of_disassembled_class(r)) for r in self._context.disassembled_classes()):
      if re.search('(?:^|\.)a$', c):
        yield Issue(detector_id=self.option, confidence='certain', cvss3_vector=self._cvss_true, summary='detected obfuscator', info1='ProGuard')
        break
    else:
      yield Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss_false, summary='lack of obfuscation')

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

  def detect(self) -> Iterable[Issue]:
    import pkg_resources
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'tlds.txt')), 'r', encoding='utf-8') as f:
      self._re_tlds = re.compile('^(?:{})$'.format('|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#'))), flags=re.IGNORECASE)

    with self._context.store() as store:
      for cl in store.query().consts(InvocationPattern('const-string', r'://|^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+|^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?$')):
        for match in self._analyzed(cl.p[1].v):
          for v in match['value']:
            yield Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss, summary=f'detected {match["type_"]}', info1=v, source=store.query().qualname_of(cl))
      for name, val in self._context.string_resources():
        for match in self._analyzed(val):
          for v in match['value']:
            yield Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss, summary=f'detected {match["type_"]}', info1=v, source='R.string.%s' % name)
