# -*- coding: utf-8 -*-
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
import itertools
import re
import os

from pubsub import pub

from trueseeing.core.code.model import InvocationPattern
from trueseeing.core.flow.data import DataFlows
from trueseeing.signature.base import Detector
from trueseeing.core.issue import Issue
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Iterable, Optional, Set, Tuple, Any, TypeVar, Dict
  T = TypeVar('T')

class SecurityFilePermissionDetector(Detector):
  option = 'security-file-permission'
  description = 'Detects insecure file creation'
  _cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/'
  _summary = 'insecure file permission'

  async def detect(self) -> None:
    with self._context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-virtual', r'Landroid/content/Context;->openFileOutput\(Ljava/lang/String;I\)')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        try:
          target_val = int(DataFlows.solved_constant_data_in_invocation(store, cl, 1), 16)
          if target_val & 3:
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='certain',
              cvss3_vector=self._cvss,
              summary=self._summary,
              info1={1: 'MODE_WORLD_READABLE', 2: 'MODE_WORLD_WRITEABLE'}[target_val],
              source=store.query().qualname_of(cl)
            ))
        except (DataFlows.NoSuchValueError):
          pass


class SecurityTlsInterceptionDetector(Detector):
  option = 'security-tls-interception'
  description = 'Detects certificate (non-)pinning'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L/'
  _cvss_info = 'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'insecure TLS connection'

  async def detect(self) -> None:
    pin_nsc = False
    if self._context.get_min_sdk_version() > 23:
      if not self._context.parsed_manifest().getroot().xpath('//application[@android:debuggable="true"]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
        pin_nsc = True

    for fn, xp in self._context.xml_resources():
      if 'network-security-config' in xp.getroot().tag.lower():
        for e in xp.xpath('.//certificates'):
          if e.attrib.get('src') == 'user':
            pin_nsc = False
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='firm',
              cvss3_vector=self._cvss,
              summary=self._summary,
              info1='user-trusting network security config detected'
            ))
          for pin in e.xpath('.//pins'):
            algo: str
            dig: str
            algo, dig = pin.attrib('digest', '(unknown)'), pin.text
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='firm',
              cvss3_vector=self._cvss_info,
              summary='explicit ceritifcate pinning',
              info1=f'{algo}:{dig}',
            ))
    if not pin_nsc:
      if not self._do_detect_plain_pins_x509():
        if not self._do_detect_plain_pins_hostnameverifier():
          pub.sendMessage('issue', issue=Issue(
            detector_id=self.option,
            confidence='firm',
            cvss3_vector=self._cvss,
            summary=self._summary,
            info1='no pinning detected'
          ))

  def _do_detect_plain_pins_x509(self) -> Set[str]:
    with self._context.store() as store:
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
        for cl in self._context.store().query().invocations(InvocationPattern('invoke-virtual', 'Ljavax/net/ssl/SSLContext;->init')):
          custom_sslcontext_detected = True
          pins = DataFlows.solved_typeset_in_invocation(store, cl, 1) & pins

        if not custom_sslcontext_detected:
          return set()
        else:
          return pins
      else:
        return pins

  def _do_detect_plain_pins_hostnameverifier(self) -> Set[str]:
    with self._context.store() as store:
      pins: Set[str] = set()
      q = store.query()
      for m in itertools.chain(store.query().methods_in_class('verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z', 'HostnameVerifier')):
        if any(q.matches_in_method(m, InvocationPattern('invoke', 'contains|equals|verify|Ljavax/net/ssl/SSLSession;->getPeerCertificates'))):
          classname = q.class_name_of(q.class_of_method(m))
          if classname:
            pins.add(classname)
      return pins


class LayoutSizeGuesser:
  _xmlns_android = '{http://schemas.android.com/apk/res/android}'
  _table = {'small':(320.0, 426.0), 'normal':(320.0, 470.0), 'large':(480.0, 640.0), 'xlarge':(720.0, 960.0)}

  def guessed_size(self, t: Any, path: str) -> float:
    dps = self._dps_from_modifiers(self._modifiers_in(path))
    for e in self._self_and_containers_of(t):
      try:
        width, height = self._width_of(e), self._height_of(e)
      except KeyError:
        try:
          ui.warn('layout_guesser: guessed_size: ignoring improper webview declaration ({0})'.format(e.attrib[f'{self._xmlns_android}id']))
          return 0.0
        except KeyError:
          ui.warn('layout_guesser: guessed_size: ignoring improper webview declaration')
          return 0.0
      else:
        if any(self._is_bound(x) for x in (width, height)):
          return self._guessed_dp(width, dps[0]) * self._guessed_dp(height, dps[1])
    else:
      return 1.0

  @classmethod
  def _dps_from_modifiers(cls, mods: Set[str]) -> Tuple[float, float]:
    try:
      x, y = cls._table[list(mods & cls._table.keys())[0]]
    except (IndexError, KeyError):
      x, y = cls._table['large']
    if 'land' in mods:
      return (y, x)
    else:
      return (x, y)

  @classmethod
  def _width_of(cls, e: Any) -> str:
    return e.attrib[f'{cls._xmlns_android}layout_width'] # type:ignore[no-any-return]

  @classmethod
  def _height_of(cls, e: Any) -> str:
    return e.attrib[f'{cls._xmlns_android}layout_height'] # type:ignore[no-any-return]

  @classmethod
  def _is_bound(cls, x: str) -> bool:
    return x not in ('fill_parent', 'match_parent', 'wrap_content')

  @classmethod
  def _guessed_dp(cls, x: str, dp: float) -> float:
    if cls._is_bound(x):
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

  @classmethod
  def _self_and_containers_of(cls, e: Any) -> Iterable[Any]:
    yield e
    e = e.getparent()
    if e is not None:
      cls._self_and_containers_of(e)

  @classmethod
  def _modifiers_in(cls, path: str) -> Set[str]:
    return [set(c.split('-')) for c in path.split(os.sep) if 'layout' in c][0]


class SecurityTamperableWebViewDetector(Detector):
  option = 'security-tamperable-webview'
  description = 'Detects tamperable WebView'
  _summary1 = 'tamperable webview'
  _summary2 = 'tamperable webview with URL'
  _cvss1 = 'CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:L/'
  _cvss2 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L/'

  _xmlns_android = '{http://schemas.android.com/apk/res/android}'

  async def detect(self) -> None:
    import lxml.etree as ET
    from functools import reduce
    with self._context.store() as store:
      targets = {'WebView','XWalkView','GeckoView'}

      more = True
      while more:
        more = False
        for cl in store.query().related_classes('|'.join(targets)):
          name = store.query().class_name_of(cl)
          if name is not None and name not in targets:
            targets.add(name)
            more = True

      for fn in (n for n in self._context.disassembled_resources() if 'layout' in n):
        with open(fn, 'rb') as f:
          r = ET.parse(f, parser=ET.XMLParser(recover=True)).getroot()
          for t in reduce(lambda x,y: x+y, (r.xpath('//{}'.format(self._context.class_name_of_dalvik_class_type(c).replace('$', '_'))) for c in targets)):
            size = LayoutSizeGuesser().guessed_size(t, fn)
            if size > 0.5:
              try:
                pub.sendMessage('issue', issue=Issue(
                  detector_id=self.option,
                  confidence='tentative',
                  cvss3_vector=self._cvss1,
                  summary=self._summary1,
                  info1='{0} (score: {1:.02f})'.format(t.attrib[f'{self._xmlns_android}id'], size),
                  source=self._context.source_name_of_disassembled_resource(fn)
                ))
              except KeyError as e:
                ui.warn(f'SecurityTamperableWebViewDetector.do_detect: missing key {e}')

      # XXX: crude detection
      for op in store.query().invocations(InvocationPattern('invoke-', ';->loadUrl')):
        qn = store.query().qualname_of(op)
        if self._context.is_qualname_excluded(qn):
          continue
        try:
          v = DataFlows.solved_constant_data_in_invocation(store, op, 0)
          if v.startswith('http://'):
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='firm',
              cvss3_vector=self._cvss2,
              summary=self._summary2,
              info1=v,
              source=store.query().qualname_of(op)
            ))
        except DataFlows.NoSuchValueError:
          pass


class SecurityInsecureWebViewDetector(Detector):
  option = 'security-insecure-webview'
  description = 'Detects insecure WebView'
  _cvss = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/'
  _cvss2 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L/'
  _cvss2b = 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/'
  _cvss3 = 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N/'
  _cvss4 = 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary1 = 'insecure Javascript interface'
  _summary2 = 'insecure mixed content mode'
  _summary2b = 'potentially insecure mixed content mode'
  _summary3 = 'insecure CSP'
  _summary4 = 'detected CSP'

  _xmlns_android = '{http://schemas.android.com/apk/res/android}'

  # FIXME: Come up with something more right
  @classmethod
  def _first(cls, xs: Iterable[T], default: Optional[T] = None) -> Optional[T]:
    try:
      return list(itertools.islice(xs, 1))[0]
    except IndexError:
      return default

  async def detect(self) -> None:
    with self._context.store() as store:
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
      if self._context.get_min_sdk_version() <= 16:
        for p in store.query().invocations(InvocationPattern('invoke-virtual', 'Landroid/webkit/WebSettings;->setJavaScriptEnabled')):
          qn = store.query().qualname_of(p)
          if self._context.is_qualname_excluded(qn):
            continue
          try:
            if DataFlows.solved_constant_data_in_invocation(store, p, 0):
              for target in targets:
                for q in store.query().invocations_in_class(p, InvocationPattern('invoke-virtual', f'{target}->addJavascriptInterface')):
                  try:
                    if DataFlows.solved_constant_data_in_invocation(store, q, 0):
                      pub.sendMessage('issue', issue=Issue(
                        detector_id=self.option,
                        confidence='firm',
                        cvss3_vector=self._cvss,
                        summary=self._summary1,
                        source=store.query().qualname_of(q)
                      ))
                  except (DataFlows.NoSuchValueError):
                    pub.sendMessage('issue', issue=Issue(
                      detector_id=self.option,
                      confidence='tentative',
                      cvss3_vector=self._cvss,
                      summary=self._summary1,
                      source=store.query().qualname_of(q)
                    ))
          except (DataFlows.NoSuchValueError):
            pass

      # https://developer.android.com/reference/android/webkit/WebSettings#setMixedContentMode(int)
      if self._context.get_min_sdk_version() >= 21:
        for q in store.query().invocations(InvocationPattern('invoke-virtual', 'Landroid/webkit/WebSettings;->setMixedContentMode')):
          qn = store.query().qualname_of(q)
          if self._context.is_qualname_excluded(qn):
            continue
          try:
            val = int(DataFlows.solved_constant_data_in_invocation(store, q, 0), 16)
            if val == 0:
              pub.sendMessage('issue', issue=Issue(
                detector_id=self.option,
                confidence='firm',
                cvss3_vector=self._cvss2,
                summary=self._summary2,
                info1='MIXED_CONTENT_ALWAYS_ALLOW',
                source=store.query().qualname_of(q)))
            elif val == 2:
              pub.sendMessage('issue', issue=Issue(
                detector_id=self.option,
                confidence='firm',
                cvss3_vector=self._cvss2b,
                summary=self._summary2b,
                info1='MIXED_CONTENT_COMPATIBILITY_MODE',
                source=store.query().qualname_of(q)))
          except (DataFlows.NoSuchValueError):
            pass
      else:
        for target in targets:
          for q in store.query().invocations(InvocationPattern('invoke-virtual', f'{target}->loadUrl')):
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='firm',
              cvss3_vector=self._cvss,
              summary=self._summary2,
              info1='mixed mode always enabled in API < 21',
              source=store.query().qualname_of(q)
            ))

      for op in store.query().invocations(InvocationPattern('invoke-', ';->loadUrl')):
        qn = store.query().qualname_of(op)
        if self._context.is_qualname_excluded(qn):
          continue
        try:
          v = DataFlows.solved_constant_data_in_invocation(store, op, 0)
          if v.startswith('file:///android_asset/'):
            path = v.replace('file:///android_asset/', 'assets/')
            with open(os.path.join(self._context.wd, path)) as f:
              content = f.read()
              m = re.search('<meta .*Content-Security-Policy.*content="(.*)?">', content, flags=re.IGNORECASE)
              csp: Optional[str] = None if m is None else m.group(1)
              if csp is None or any([(x in csp.lower()) for x in ('unsafe', 'http:')]):
                pub.sendMessage('issue', issue=Issue(
                  detector_id=self.option,
                  confidence='firm',
                  cvss3_vector=self._cvss3,
                  summary=self._summary3,
                  info1=path,
                  info2='default' if csp is None else csp,
                  source=store.query().qualname_of(op)
                ))
              else:
                pub.sendMessage('issue', issue=Issue(
                  detector_id=self.option,
                  confidence='firm',
                  cvss3_vector=self._cvss4,
                  summary=self._summary4,
                  info1=path,
                  info2=csp,
                  source=store.query().qualname_of(op)
                ))
        except DataFlows.NoSuchValueError:
          pass

class FormatStringDetector(Detector):
  option = 'security-format-string'
  description = 'Detects format string usages'
  _summary = 'detected format string'
  _cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def _analyzed(self, x: str) -> Iterable[Dict[str, Any]]:
    if re.search(r'%s', x):
      if re.search(r'(://|[<>/&?])', x):
        yield dict(confidence='firm', value=x)

  async def detect(self) -> None:
    with self._context.store() as store:
      for cl in store.query().consts(InvocationPattern('const-string', r'%s')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        for t in self._analyzed(cl.p[1].v):
          pub.sendMessage('issue', issue=Issue(
            detector_id=self.option,
            confidence=t['confidence'],
            cvss3_vector=self._cvss,
            summary=self._summary,
            info1=t['value'],
            source=store.query().qualname_of(cl)
          ))
      for name, val in self._context.string_resources():
        for t in self._analyzed(val):
          pub.sendMessage('issue', issue=Issue(
            detector_id=self.option,
            confidence=t['confidence'],
            cvss3_vector=self._cvss,
            summary=self._summary,
            info1=t['value'],
            source=f'R.string.{name}'
          ))

class LogDetector(Detector):
  option = 'security-log'
  description = 'Detects logging activities'
  _summary = 'detected logging'
  _cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/'

  async def detect(self) -> None:
    with self._context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-', r'L.*->([dwie]|debug|error|exception|warning|info|notice|wtf)\(Ljava/lang/String;Ljava/lang/String;.*?Ljava/lang/(Throwable|.*?Exception);|L.*;->print(ln)?\(Ljava/lang/String;|LException;->printStackTrace\(')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        if 'print' not in cl.p[1].v:
          try:
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='tentative',
              cvss3_vector=self._cvss,
              summary=self._summary,
              info1=cl.p[1].v,
              info2=DataFlows.solved_constant_data_in_invocation(store, cl, 1),
              source=store.query().qualname_of(cl)
            ))
          except (DataFlows.NoSuchValueError):
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='tentative',
              cvss3_vector=self._cvss,
              summary=self._summary,
              info1=cl.p[1].v,
              source=store.query().qualname_of(cl)
            ))
        elif 'Exception;->' not in cl.p[1].v:
          try:
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='tentative',
              cvss3_vector=self._cvss,
              summary=self._summary,
              info1=cl.p[1].v,
              info2=DataFlows.solved_constant_data_in_invocation(store, cl, 0),
              source=store.query().qualname_of(cl)
            ))
          except (DataFlows.NoSuchValueError):
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='tentative',
              cvss3_vector=self._cvss,
              summary=self._summary,
              info1=cl.p[1].v,
              source=store.query().qualname_of(cl)
            ))
        else:
          pub.sendMessage('issue', issue=Issue(
            detector_id=self.option,
            confidence='tentative',
            cvss3_vector=self._cvss,
            summary=self._summary,
            info1=cl.p[1].v,
            source=store.query().qualname_of(cl)
          ))

class ADBProbeDetector(Detector):
  option = 'security-adb-detect'
  description = 'Detects probe of adbd status.'
  _cvss = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'USB debugging detection'
  _synopsis = 'The application is probing for USB debugging (adbd.)'

  async def detect(self) -> None:
    with self._context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-', r'^Landroid/provider/Settings\$(Global|Secure);->getInt\(')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        for found in DataFlows.solved_possible_constant_data_in_invocation(store, cl, 1):
          if found == 'adb_enabled':
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='firm',
              cvss3_vector=self._cvss,
              summary=self._summary,
              source=store.query().qualname_of(cl),
              synopsis=self._synopsis,
            ))

class ClientXSSJQDetector(Detector):
  option = 'security-cxss-jq'
  description = 'Detects potential client-side XSS vector in JQuery-based apps'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N/'
  _summary = 'Potential client-side XSS (JQuery)'
  _synopsis = "The application pours literal HTML in JQuery context."

  async def detect(self) -> None:
    files = [fn for fn in glob.glob(os.path.join(self._context.wd, 'assets', '**/*.js'), recursive=True) if os.path.isfile(fn)]
    for fn in files:
      with open(fn, 'r') as f:
        for l in f:
          for m in re.finditer(r'\.html\(', l):
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              confidence='firm',
              cvss3_vector=self._cvss,
              summary=self._summary,
              info1='{match} ({rfn})'.format(rfn=os.path.relpath(fn, self._context.wd), match=l),
              synopsis=self._synopsis,
            ))

class SecurityFileWriteDetector(Detector):
  option = 'security-file-write'
  description = 'Detects file creation'
  _cvss1 = 'CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/'
  _summary1 = 'detected potential logging into file'
  _synopsis1 = 'The application is potentially logging into file.'
  _cvss2 = 'CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary2 = 'open files for writing'
  _synopsis2 = 'The application opens files for writing.'

  async def detect(self) -> None:
    with self._context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-virtual', r'Landroid/content/Context;->openFileOutput\(Ljava/lang/String;I\)')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        try:
          target_val = DataFlows.solved_constant_data_in_invocation(store, cl, 0)
        except DataFlows.NoSuchValueError:
          target_val = '(unknown name)'

        if re.search(r'debug|log|info|report|screen|err|tomb|drop', target_val):
          pub.sendMessage('issue', issue=Issue(
            detector_id=self.option,
            confidence='certain',
            cvss3_vector=self._cvss1,
            summary=self._summary1,
            synopsis=self._synopsis1,
            info1=target_val,
            source=store.query().qualname_of(cl)
          ))
        else:
          pub.sendMessage('issue', issue=Issue(
            detector_id=self.option,
            confidence='certain',
            cvss3_vector=self._cvss2,
            summary=self._summary2,
            synopsis=self._synopsis2,
            info1=target_val,
            source=store.query().qualname_of(cl)
          ))

      for cl in store.query().invocations(InvocationPattern('invoke-direct', r'java/io/File(Writer|OutputStream)?;-><init>\(Ljava/lang/String;\)')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        try:
          target_val = DataFlows.solved_constant_data_in_invocation(store, cl, 0)

          if re.search(r'debug|log|info|report|screen|err|tomb|drop', target_val):
            if not re.search(r'^/proc/|^/sys/', target_val):
              pub.sendMessage('issue', issue=Issue(
                detector_id=self.option,
                confidence='tentative',
                cvss3_vector=self._cvss1,
                summary=self._summary1,
                synopsis=self._synopsis1,
                info1=target_val,
                source=store.query().qualname_of(cl)
              ))
        except DataFlows.NoSuchValueError:
          target_val = '(unknown name)'

class SecurityInsecureRootedDetector(Detector):
  option = 'security-insecure-rooted'
  description = 'Detects insecure rooted device probes'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  _pat = r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+'

  async def detect(self) -> None:
    with self._context.store() as store:
      found: Set[str] = set()
      attestations: Set[str] = set()

      for cl in store.query().invocations(InvocationPattern('invoke-', r'Lcom/google/android/gms/safetynet/SafetyNetClient;->attest\(\[BLjava/lang/String;\)')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        # XXX: crude detection
        verdict_accesses = list(store.query().consts_in_class(cl, InvocationPattern('const-string', r'ctsProfileMatch|basicIntegrity')))
        if verdict_accesses and qn is not None:
          attestations.add(qn)

      for cl in store.query().consts(InvocationPattern('const-string', self._pat)):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        found = found.union([m.group(0) for m in re.finditer(self._pat, cl.p[1].v)])
      for name, val in self._context.string_resources():
        found = found.union([m.group(0) for m in re.finditer(self._pat, val)])

      path_based_detection_attempt: Set[str] = set()
      for s in found:
        if re.search(r'Sup|su|xbin|sbin|root', s):
          path_based_detection_attempt.add(s)
      if path_based_detection_attempt and not attestations:
        pub.sendMessage('issue', issue=Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss, summary='manual root detections without remote attestations', info1=','.join(path_based_detection_attempt)))
      elif attestations and not path_based_detection_attempt:
        pub.sendMessage('issue', issue=Issue(detector_id=self.option, confidence='firm', cvss3_vector=self._cvss, summary='remote attestations without manual root detections', info1=','.join(attestations)))
