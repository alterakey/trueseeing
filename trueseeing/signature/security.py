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
# * Security: Escaratable cross-site scripting (API < 17) (WIP: API version conditions)
# * Security: TLS interception
# * Security: Tamperable WebViews
# * Security: Insecure permissions
# * Security: Insecure libraries

from __future__ import annotations
from typing import TYPE_CHECKING

import functools
import itertools
import lxml.etree as ET
import re
import os

from trueseeing.core.flow.code import InvocationPattern
from trueseeing.core.flow.data import DataFlows
from trueseeing.signature.base import Detector
from trueseeing.core.issue import IssueConfidence, Issue
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Iterable, Optional, Set, Tuple, Any, List, Union, TypeVar, Dict
  T = TypeVar('T')

class SecurityFilePermissionDetector(Detector):
  option = 'security-file-permission'
  description = 'Detects insecure file creation'
  cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/'

  def detect(self) -> Iterable[Issue]:
    with self.context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-virtual', 'Landroid/content/Context;->openFileOutput\(Ljava/lang/String;I\)')):
        try:
          target_val = int(DataFlows.solved_constant_data_in_invocation(store, cl, 1), 16)
          if target_val & 3:
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.CERTAIN,
              cvss3_vector=self.cvss,
              summary='insecure file permission',
              info1={1: 'MODE_WORLD_READABLE', 2: 'MODE_WORLD_WRITEABLE'}[target_val],
              source=store.query().qualname_of(cl)
            )
        except (DataFlows.NoSuchValueError):
          pass


class SecurityTlsInterceptionDetector(Detector):
  option = 'security-tls-interception'
  description = 'Detects certificate (non-)pinning'
  cvss = 'CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:N/'

  def detect(self) -> Iterable[Issue]:
    if self.context.get_min_sdk_version() <= 23:
      if not self.do_detect_plain_pins_x509():
        if not self.do_detect_plain_pins_hostnameverifier():
          yield Issue(
            detector_id=self.option,
            confidence=IssueConfidence.CERTAIN,
            cvss3_vector=self.cvss,
            summary='insecure TLS connection',
            info1='no pinning detected'
          )

  def do_detect_plain_pins_x509(self) -> Set[str]:
    with self.context.store() as store:
      pins: Set[str] = set()
      q = store.query()
      for m in store.query().methods_in_class('checkServerTrusted', 'X509TrustManager'):
        if any(q.matches_in_method(m, InvocationPattern('verify', ''))):
          classname = q.class_name_of(q.class_of_method(m))
          if classname:
            pins.add(classname)
        if any(q.matches_in_method(m, InvocationPattern('throw', ''))):
          classname = q.class_name_of(q.class_of_method(m))
          if classname:
            pins.add(classname)

      if pins:
        # XXX crude detection
        custom_sslcontext_detected = False
        for cl in self.context.store().query().invocations(InvocationPattern('invoke-virtual', 'Ljavax/net/ssl/SSLContext;->init')):
          custom_sslcontext_detected = True
          pins = DataFlows.solved_typeset_in_invocation(store, cl, 1) & pins

        if not custom_sslcontext_detected:
          return set()
        else:
          return pins
      else:
        return pins

  def do_detect_plain_pins_hostnameverifier(self) -> Set[str]:
    with self.context.store() as store:
      pins: Set[str] = set()
      q = store.query()
      for m in itertools.chain(store.query().methods_in_class('verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z', 'HostnameVerifier')):
        if any(q.matches_in_method(m, InvocationPattern('invoke', 'contains|equals|verify|Ljavax/net/ssl/SSLSession;->getPeerCertificates'))):
          classname = q.class_name_of(q.class_of_method(m))
          if classname:
            pins.add(classname)
      return pins


class LayoutSizeGuesser:
  xmlns_android = '{http://schemas.android.com/apk/res/android}'
  table = {'small':(320.0, 426.0), 'normal':(320.0, 470.0), 'large':(480.0, 640.0), 'xlarge':(720.0, 960.0)}

  def guessed_size(self, t: Any, path: str) -> float:
    def dps_from_modifiers(mods: Set[str]) -> Tuple[float, float]:
      try:
        x, y = self.table[list(mods & self.table.keys())[0]]
      except (IndexError, KeyError):
        x, y = self.table['large']
      if 'land' in mods:
        return (y, x)
      else:
        return (x, y)

    def width_of(e: Any) -> str:
      return e.attrib[f'{self.xmlns_android}layout_width'] # type:ignore[no-any-return]

    def height_of(e: Any) -> str:
      return e.attrib[f'{self.xmlns_android}layout_height'] # type:ignore[no-any-return]

    def is_bound(x: str) -> bool:
      return x not in ('fill_parent', 'match_parent', 'wrap_content')

    def guessed_dp(x: str, dp: float) -> float:
      if is_bound(x):
        try:
          return float(re.sub(r'di?p$', '', x)) / float(dp)
        except ValueError:
          try:
            ui.debug("layout_guesser: guessed_size: guessed_dp: warning: ignoring non-dp suffix ({!s})".format(x))
            return float(re.sub(r'[^0-9-]', '', x)) / float(dp)
          except ValueError:
            ui.debug("layout_guesser: guessed_size: guessed_dp: warning: ignoring unknown dimension")
            return 0.0
      else:
        return dp

    def self_and_containers_of(e: Any) -> Iterable[Any]:
      yield e
      e = e.getparent()
      if e is not None:
        self_and_containers_of(e)

    def modifiers_in(path: str) -> Set[str]:
      return [set(c.split('-')) for c in path.split(os.sep) if 'layout' in c][0]

    dps = dps_from_modifiers(modifiers_in(path))
    for e in self_and_containers_of(t):
      try:
        width, height = width_of(e), height_of(e)
      except KeyError:
        try:
          ui.warn('layout_guesser: guessed_size: ignoring improper webview declaration ({0})'.format(e.attrib[f'{self.xmlns_android}id']))
          return 0.0
        except KeyError:
          ui.warn('layout_guesser: guessed_size: ignoring improper webview declaration')
          return 0.0
      else:
        if any(is_bound(x) for x in (width_of(e), height_of(e))):
          return guessed_dp(width_of(e), dps[0]) * guessed_dp(height_of(e), dps[1])
    else:
      return 1.0

class SecurityTamperableWebViewDetector(Detector):
  option = 'security-tamperable-webview'
  description = 'Detects tamperable WebView'
  cvss1 = 'CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N/'
  cvss2 = 'CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N/'

  xmlns_android = '{http://schemas.android.com/apk/res/android}'

  def detect(self) -> Iterable[Issue]:
    with self.context.store() as store:
      targets = {'WebView','XWalkView','GeckoView'}

      more = True
      while more:
        more = False
        for cl in store.query().related_classes('|'.join(targets)):
          name = store.query().class_name_of(cl)
          if name is not None and name not in targets:
            targets.add(name)
            more = True

      for fn in (n for n in self.context.disassembled_resources() if 'layout' in n):
        with open(fn, 'rb') as f:
          r = ET.parse(f, parser=ET.XMLParser(recover=True)).getroot()
          for t in functools.reduce(lambda x,y: x+y, (r.xpath('//{}'.format(self.context.class_name_of_dalvik_class_type(c).replace('$', '_'))) for c in targets)):
            size = LayoutSizeGuesser().guessed_size(t, fn)
            if size > 0.5:
              try:
                yield Issue(
                  detector_id=self.option,
                  confidence=IssueConfidence.TENTATIVE,
                  cvss3_vector=self.cvss1,
                  summary='tamperable webview',
                  info1='{0} (score: {1:.02f})'.format(t.attrib[f'{self.xmlns_android}id'], size),
                  source=self.context.source_name_of_disassembled_resource(fn)
                )
              except KeyError as e:
                ui.warn(f'SecurityTamperableWebViewDetector.do_detect: missing key {e}')

      # XXX: crude detection
      for op in store.query().invocations(InvocationPattern('invoke-', ';->loadUrl')):
        try:
          v = DataFlows.solved_constant_data_in_invocation(store, op, 0)
          if v.startswith('http://'):
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.FIRM,
              cvss3_vector=self.cvss2,
              summary='tamperable webview with URL',
              info1=v,
              source=store.query().qualname_of(op)
            )
        except DataFlows.NoSuchValueError:
          pass


class SecurityInsecureWebViewDetector(Detector):
  option = 'security-insecure-webview'
  description = 'Detects insecure WebView'
  cvss = 'CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H/'

  xmlns_android = '{http://schemas.android.com/apk/res/android}'

  # FIXME: Come up with something more right
  @staticmethod
  def first(xs: Iterable[T], default: Optional[T] = None) -> Optional[T]:
    try:
      return list(itertools.islice(xs, 1))[0]
    except IndexError:
      return default

  def detect(self) -> Iterable[Issue]:
    with self.context.store() as store:
      targets = set()
      seeds = {'WebView','XWalkView','GeckoView'}

      more = True
      while more:
        more = False
        for cl in store.query().related_classes('|'.join(seeds)):
          name = store.query().class_name_of(cl)
          if name not in targets:
            targets.add(name)
            more = True
      for seed in seeds:
        targets.add(f'L.*{seed};')

      # XXX: Crude detection
      # https://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface(java.lang.Object,%2520java.lang.String)
      if self.context.get_min_sdk_version() <= 16:
        for p in store.query().invocations(InvocationPattern('invoke-virtual', 'Landroid/webkit/WebSettings;->setJavaScriptEnabled')):
          try:
            if DataFlows.solved_constant_data_in_invocation(store, p, 0):
              for target in targets:
                for q in store.query().invocations_in_class(p, InvocationPattern('invoke-virtual', f'{target}->addJavascriptInterface')):
                  try:
                    if DataFlows.solved_constant_data_in_invocation(store, q, 0):
                      yield Issue(
                        detector_id=self.option,
                        confidence=IssueConfidence.FIRM,
                        cvss3_vector=self.cvss,
                        summary='insecure Javascript interface',
                        source=store.query().qualname_of(q)
                      )
                  except (DataFlows.NoSuchValueError):
                      yield Issue(
                        detector_id=self.option,
                        confidence=IssueConfidence.TENTATIVE,
                        cvss3_vector=self.cvss,
                        summary='insecure Javascript interface',
                        source=store.query().qualname_of(q)
                      )
          except (DataFlows.NoSuchValueError):
            pass

        # https://developer.android.com/reference/android/webkit/WebSettings#setMixedContentMode(int)
        if self.context.get_min_sdk_version() <= 20:
          for q in store.query().invocations_in_class(p, InvocationPattern('invoke-virtual', 'Landroid/webkit/WebSettings;->setMixedContentMode')):
            try:
              val = int(DataFlows.solved_constant_data_in_invocation(store, q, 0), 16)
              if val == 0:
                yield Issue(
                  detector_id=self.option,
                  confidence=IssueConfidence.FIRM,
                  cvss3_vector=self.cvss,
                  summary='insecure mixed content mode',
                  info1='MIXED_CONTENT_ALWAYS_ALLOW',
                  source=store.query().qualname_of(q))
            except (DataFlows.NoSuchValueError):
              pass

class FormatStringDetector(Detector):
  option = 'security-format-string'
  description = 'Detects format string usages'
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def analyzed(self, x: str) -> Iterable[Dict[str, Any]]:
    if re.search(r'%s', x):
      if re.search(r'(://|[<>/&?])', x):
        yield dict(confidence=IssueConfidence.FIRM, value=x)

  def detect(self) -> Iterable[Issue]:
    with self.context.store() as store:
      for cl in store.query().consts(InvocationPattern('const-string', r'%s')):
        for t in self.analyzed(cl.p[1].v):
          yield Issue(
            detector_id=self.option,
            confidence=t['confidence'],
            cvss3_vector=self.cvss,
            summary='detected format string',
            info1=t['value'],
            source=store.query().qualname_of(cl)
          )
      for name, val in self.context.string_resources():
        for t in self.analyzed(val):
          yield Issue(
            detector_id=self.option,
            confidence=t['confidence'],
            cvss3_vector=self.cvss,
            summary='detected format string',
            info1=t['value'],
            source=f'R.string.{name}'
          )

class LogDetector(Detector):
  option = 'security-log'
  description = 'Detects logging activities'
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/'

  def detect(self) -> Iterable[Issue]:
    with self.context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-', 'L.*->([dwie]|debug|error|exception|warning|info|notice|wtf)\(Ljava/lang/String;Ljava/lang/String;.*?Ljava/lang/(Throwable|.*?Exception);|L.*;->print(ln)?\(Ljava/lang/String;|LException;->printStackTrace\(')):
        if 'print' not in cl.p[1].v:
          try:
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.TENTATIVE,
              cvss3_vector=self.cvss,
              summary='detected logging',
              info1=cl.p[1].v,
              info2=DataFlows.solved_constant_data_in_invocation(store, cl, 1),
              source=store.query().qualname_of(cl)
            )
          except (DataFlows.NoSuchValueError):
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.TENTATIVE,
              cvss3_vector=self.cvss,
              summary='detected logging',
              info1=cl.p[1].v,
              source=store.query().qualname_of(cl)
            )
        elif 'Exception;->' not in cl.p[1].v:
          try:
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.TENTATIVE,
              cvss3_vector=self.cvss,
              summary='detected logging',
              info1=cl.p[1].v,
              info2=DataFlows.solved_constant_data_in_invocation(store, cl, 0),
              source=store.query().qualname_of(cl)
            )
          except (DataFlows.NoSuchValueError):
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.TENTATIVE,
              cvss3_vector=self.cvss,
              summary='detected logging',
              info1=cl.p[1].v,
              source=store.query().qualname_of(cl)
            )
        else:
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.TENTATIVE,
              cvss3_vector=self.cvss,
              summary='detected logging',
              info1=cl.p[1].v,
              source=store.query().qualname_of(cl)
            )
