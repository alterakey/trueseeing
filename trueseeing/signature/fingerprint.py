# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
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

import collections
import itertools
import os
import re
import logging
from trueseeing.flow.code import InvocationPattern
from trueseeing.flow.data import DataFlows
from trueseeing.signature.base import Detector
from trueseeing.issue import IssueConfidence, Issue

import pkg_resources

log = logging.getLogger(__name__)

class LibraryDetector(Detector):
  option = 'detect-library'
  description = 'Detects libraries'
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

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

  def do_detect(self):
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

    yield from (
      Issue(
        detector_id=self.option,
        confidence=IssueConfidence.FIRM,
        cvss3_vector=self.cvss,
        summary='detected library',
        info1='%s (score: %d)' % (p, len(packages[p])),
      ) for p in sorted(packages.keys())
    )


class ProGuardDetector(Detector):
  option = 'detect-obfuscator'
  description = 'Detects obfuscators'
  cvss_true = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  cvss_false = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/'

  def class_name_of(self, path):
    return path.replace('.smali', '').replace('/', '.')

  def detect(self):
    for c in (self.class_name_of(self.context.source_name_of_disassembled_class(r)) for r in self.context.disassembled_classes()):
      if re.search('(?:^|\.)a$', c):
        yield Issue(detector_id=self.option, confidence=IssueConfidence.CERTAIN, cvss3_vector=self.cvss_true, summary='detected obfuscator', info1='ProGuard')
        break
    else:
      yield Issue(detector_id=self.option, confidence=IssueConfidence.FIRM, cvss3_vector=self.cvss_false, summary='lack of obfuscation')

class FakeToken:
  def __init__(self, v, p):
    self.v = v
    self.p = p

class UrlLikeDetector(Detector):
  option = 'detect-url'
  description = 'Detects URL-like strings'
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

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
        if not re.search(r'^android\.(intent|media)\.', hostlike):
          yield dict(type_='possible FQDN', value=[hostlike])

  def do_detect(self):
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'tlds.txt')), 'r', encoding='utf-8') as f:
      self.re_tlds = re.compile('^(?:%s)$' % '|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#')), flags=re.IGNORECASE)

    with self.context.store() as store:
      for cl in store.query().consts(InvocationPattern('const-string', r'://|^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+|^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?$')):
        for match in self.analyzed(cl.p[1].v):
          for v in match['value']:
            yield Issue(detector_id=self.option, confidence=IssueConfidence.FIRM, cvss3_vector=self.cvss, summary='detected %s' % match['type_'], info1=v, source=store.query().qualname_of(cl))
      for name, val in self.context.string_resources():
        for match in self.analyzed(val):
          for v in match['value']:
            yield Issue(detector_id=self.option, confidence=IssueConfidence.FIRM, cvss3_vector=self.cvss, summary='detected %s' % match['type_'], info1=v, source='R.string.%s' % name)
