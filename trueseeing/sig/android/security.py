from __future__ import annotations
from typing import TYPE_CHECKING

import itertools
import io
import re
import os

from trueseeing.core.android.model.code import InvocationPattern
from trueseeing.core.android.analysis.flow import DataFlow
from trueseeing.core.model.sig import SignatureMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Iterable, Optional, Set, Tuple, Any, TypeVar, Dict
  from trueseeing.api import Signature, SignatureHelper, SignatureMap
  from trueseeing.core.model.issue import IssueConfidence
  T = TypeVar('T')

class SecurityFilePermissionDetector(SignatureMixin):
  _id = 'security-file-permission'
  _cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/'
  _summary = 'insecure file permission'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return SecurityFilePermissionDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects insecure file creation')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.invocations(InvocationPattern('invoke-virtual', r'Landroid/content/Context;->openFileOutput\(Ljava/lang/String;I\)')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      try:
        target_val = int(DataFlow(q).solved_constant_data_in_invocation(cl, 1), 16)
        if target_val & 3:
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cfd='certain',
            cvss=self._cvss,
            title=self._summary,
            info0={1: 'MODE_WORLD_READABLE', 2: 'MODE_WORLD_WRITEABLE'}[target_val],
            aff0=q.qualname_of(cl)
          ))
      except (DataFlow.NoSuchValueError):
        pass


class SecurityTlsInterceptionDetector(SignatureMixin):
  _id = 'security-tls-interception'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L/'
  _cvss_info = 'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'insecure TLS connection'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return SecurityTlsInterceptionDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects certificate (non-)pinning')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    pin_nsc = False
    if context.get_min_sdk_version() > 23:
      if not context.parsed_manifest().xpath('//application[@android:debuggable="true"]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
        pin_nsc = True

    for fn, xp in context.xml_resources():
      if 'network-security-config' in xp.tag.lower():
        for e in xp.xpath('.//certificates'):
          if e.attrib.get('src') == 'user':
            pin_nsc = False
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cvss=self._cvss,
              title=self._summary,
              info0='user-trusting network security config detected'
            ))
          for pin in e.xpath('.//pins'):
            algo: str
            dig: str
            algo, dig = pin.attrib('digest', '(unknown)'), pin.text
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cvss=self._cvss_info,
              title='explicit ceritifcate pinning',
              info0=f'{algo}:{dig}',
            ))
    if not pin_nsc:
      if not self._do_detect_plain_pins_x509():
        if not self._do_detect_plain_pins_hostnameverifier():
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cvss=self._cvss,
            title=self._summary,
            info0='no pinning detected'
          ))

  def _do_detect_plain_pins_x509(self) -> Set[str]:
    context = self._helper.get_context()
    pins: Set[str] = set()
    store = context.store()
    q = store.query()
    for m in q.methods_in_class('checkServerTrusted', 'X509TrustManager'):
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
      for cl in q.invocations(InvocationPattern('invoke-virtual', 'Ljavax/net/ssl/SSLContext;->init')):
        custom_sslcontext_detected = True
        pins = DataFlow(q).solved_typeset_in_invocation(cl, 1) & pins

      if not custom_sslcontext_detected:
        return set()
      else:
        return pins
    else:
      return pins

  def _do_detect_plain_pins_hostnameverifier(self) -> Set[str]:
    context = self._helper.get_context()
    pins: Set[str] = set()
    q = context.store().query()
    for m in itertools.chain(q.methods_in_class('verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z', 'HostnameVerifier')):
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


class SecurityTamperableWebViewDetector(SignatureMixin):
  _id = 'security-tamperable-webview'
  description = 'Detects tamperable WebView'
  _summary1 = 'tamperable webview'
  _summary2 = 'tamperable webview with URL'
  _cvss1 = 'CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:L/'
  _cvss2 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L/'

  _xmlns_android = '{http://schemas.android.com/apk/res/android}'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return SecurityTamperableWebViewDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects tamperable WebView')}

  async def detect(self) -> None:
    import lxml.etree as ET
    from functools import reduce

    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    targets = {'WebView','XWalkView','GeckoView'}

    more = True
    while more:
      more = False
      for cl in q.related_classes('|'.join(targets)):
        name = q.class_name_of(cl)
        if name is not None and name not in targets:
          targets.add(name)
          more = True

    for fn, blob in q.file_enum('%/res/%layout%.xml'):
      r = ET.fromstring(blob, parser=ET.XMLParser(recover=True))
      for t in reduce(lambda x,y: x+y, (r.xpath('//{}'.format(context.class_name_of_dalvik_class_type(c).replace('$', '_'))) for c in targets)):
        size = LayoutSizeGuesser().guessed_size(t, fn)
        if size > 0.5:
          try:
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cfd='tentative',
              cvss=self._cvss1,
              title=self._summary1,
              info0='{0} (score: {1:.02f})'.format(t.attrib[f'{self._xmlns_android}id'], size),
              aff0=context.source_name_of_disassembled_resource(fn)
            ))
          except KeyError as e:
            ui.warn(f'SecurityTamperableWebViewDetector.do_detect: missing key {e}')

    # XXX: crude detection
    for op in q.invocations(InvocationPattern('invoke-', ';->loadUrl')):
      qn = q.qualname_of(op)
      if context.is_qualname_excluded(qn):
        continue
      try:
        v = DataFlow(q).solved_constant_data_in_invocation(op, 0)
        if v.startswith('http://'):
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cvss=self._cvss2,
            title=self._summary2,
            info0=v,
            aff0=q.qualname_of(op)
          ))
      except DataFlow.NoSuchValueError:
        pass


class SecurityInsecureWebViewDetector(SignatureMixin):
  _id = 'security-insecure-webview'
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

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return SecurityInsecureWebViewDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect,d='Detects insecure WebView')}

  # FIXME: Come up with something more right
  @classmethod
  def _first(cls, xs: Iterable[T], default: Optional[T] = None) -> Optional[T]:
    try:
      return list(itertools.islice(xs, 1))[0]
    except IndexError:
      return default

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    query = store.query()

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
    if context.get_min_sdk_version() <= 16:
      for p in query.invocations(InvocationPattern('invoke-virtual', 'Landroid/webkit/WebSettings;->setJavaScriptEnabled')):
        qn = query.qualname_of(p)
        if context.is_qualname_excluded(qn):
          continue
        try:
          if DataFlow(query).solved_constant_data_in_invocation(p, 0):
            for target in targets:
              for q in query.invocations_in_class(p, InvocationPattern('invoke-virtual', f'{target}->addJavascriptInterface')):
                try:
                  if DataFlow(query).solved_constant_data_in_invocation(q, 0):
                    self._helper.raise_issue(self._helper.build_issue(
                      sigid=self._id,
                      cvss=self._cvss,
                      title=self._summary1,
                      aff0=query.qualname_of(q)
                    ))
                except (DataFlow.NoSuchValueError):
                  self._helper.raise_issue(self._helper.build_issue(
                    sigid=self._id,
                    cfd='tentative',
                    cvss=self._cvss,
                    title=self._summary1,
                    aff0=query.qualname_of(q)
                  ))
        except (DataFlow.NoSuchValueError):
          pass

    # https://developer.android.com/reference/android/webkit/WebSettings#setMixedContentMode(int)
    if context.get_min_sdk_version() >= 21:
      for q in query.invocations(InvocationPattern('invoke-virtual', 'Landroid/webkit/WebSettings;->setMixedContentMode')):
        qn = query.qualname_of(q)
        if context.is_qualname_excluded(qn):
          continue
        try:
          val = int(DataFlow(query).solved_constant_data_in_invocation(q, 0), 16)
          if val == 0:
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cvss=self._cvss2,
              title=self._summary2,
              info0='MIXED_CONTENT_ALWAYS_ALLOW',
              aff0=query.qualname_of(q)))
          elif val == 2:
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cvss=self._cvss2b,
              title=self._summary2b,
              info0='MIXED_CONTENT_COMPATIBILITY_MODE',
              aff0=query.qualname_of(q)))
        except (DataFlow.NoSuchValueError):
          pass
    else:
      for target in targets:
        for q in query.invocations(InvocationPattern('invoke-virtual', f'{target}->loadUrl')):
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cvss=self._cvss,
            title=self._summary2,
            info0='mixed mode always enabled in API < 21',
            aff0=query.qualname_of(q)
          ))

    for op in query.invocations(InvocationPattern('invoke-', ';->loadUrl')):
      qn = query.qualname_of(op)
      if context.is_qualname_excluded(qn):
        continue
      try:
        v = DataFlow(query).solved_constant_data_in_invocation(op, 0)
        if v.startswith('file:///android_asset/'):
          path = v.replace('file:///android_asset/', 'assets/')
          blob = query.file_get(f'root/{path}')
          if blob is not None:
            content = blob.decode('utf-8', errors='ignore')
            m = re.search('<meta .*Content-Security-Policy.*content="(.*)?">', content, flags=re.IGNORECASE)
            csp: Optional[str] = None if m is None else m.group(1)
            if csp is None or any([(x in csp.lower()) for x in ('unsafe', 'http:')]):
              self._helper.raise_issue(self._helper.build_issue(
                sigid=self._id,
                cvss=self._cvss3,
                title=self._summary3,
                info0=path,
                info1='default' if csp is None else csp,
                aff0=query.qualname_of(op)
              ))
            else:
              self._helper.raise_issue(self._helper.build_issue(
                sigid=self._id,
                cvss=self._cvss4,
                title=self._summary4,
                info0=path,
                info1=csp,
                aff0=query.qualname_of(op)
              ))
      except DataFlow.NoSuchValueError:
        pass

class FormatStringDetector(SignatureMixin):
  _id = 'security-format-string'
  _summary = 'detected format string'
  _cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return FormatStringDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects format string usages')}

  def _analyzed(self, x: str) -> Iterable[Dict[str, Any]]:
    if re.search(r'%s', x):
      if re.search(r'(://|[<>/&?])', x):
        yield dict(cfd='firm', value=x)

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    q = context.store().query()
    for cl in q.consts(InvocationPattern('const-string', r'%s')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      for t in self._analyzed(cl.p[1].v):
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd=t['cfd'],
          cvss=self._cvss,
          title=self._summary,
          info0=t['value'],
          aff0=q.qualname_of(cl)
        ))
    for name, val in context.string_resources():
      for t in self._analyzed(val):
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd=t['cfd'],
          cvss=self._cvss,
          title=self._summary,
          info0=t['value'],
          aff0=f'R.string.{name}'
        ))

class LogDetector(SignatureMixin):
  _id = 'security-log'
  _summary = 'detected logging'
  _cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return LogDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects logging activities')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.invocations(InvocationPattern('invoke-', r'L.*->([dwie]|debug|error|exception|warning|info|notice|wtf)\(Ljava/lang/String;Ljava/lang/String;.*?Ljava/lang/(Throwable|.*?Exception);|L.*;->print(ln)?\(Ljava/lang/String;|LException;->printStackTrace\(')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      if 'print' not in cl.p[1].v:
        try:
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cfd='tentative',
            cvss=self._cvss,
            title=self._summary,
            info0=cl.p[1].v,
            info1=DataFlow(q).solved_constant_data_in_invocation(cl, 1),
            aff0=q.qualname_of(cl)
          ))
        except (DataFlow.NoSuchValueError):
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cfd='tentative',
            cvss=self._cvss,
            title=self._summary,
            info0=cl.p[1].v,
            aff0=q.qualname_of(cl)
          ))
      elif 'Exception;->' not in cl.p[1].v:
        try:
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cfd='tentative',
            cvss=self._cvss,
            title=self._summary,
            info0=cl.p[1].v,
            info1=DataFlow(q).solved_constant_data_in_invocation(cl, 0),
            aff0=q.qualname_of(cl)
          ))
        except (DataFlow.NoSuchValueError):
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cfd='tentative',
            cvss=self._cvss,
            title=self._summary,
            info0=cl.p[1].v,
            aff0=q.qualname_of(cl)
          ))
      else:
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='tentative',
          cvss=self._cvss,
          title=self._summary,
          info0=cl.p[1].v,
          aff0=q.qualname_of(cl)
        ))

class ADBProbeDetector(SignatureMixin):
  _id = 'security-adb-detect'
  _cvss = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'USB debugging detection'
  _synopsis = 'The application is probing for USB debugging (adbd.)'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ADBProbeDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects probe of adbd status.')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.invocations(InvocationPattern('invoke-', r'^Landroid/provider/Settings\$(Global|Secure);->getInt\(')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      for found in DataFlow(q).solved_possible_constant_data_in_invocation(cl, 1):
        if found == 'adb_enabled':
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cvss=self._cvss,
            title=self._summary,
            aff0=q.qualname_of(cl),
            summary=self._synopsis,
          ))

class ClientXSSJQDetector(SignatureMixin):
  _id = 'security-cxss-jq'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N/'
  _summary = 'Potential client-side XSS (JQuery)'
  _synopsis = "The application pours literal HTML in JQuery context."

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ClientXSSJQDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects potential client-side XSS vector in JQuery-based apps')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    for fn, blob in context.store().query().file_enum(pat='root/assets/%.js'):
      f = io.StringIO(blob.decode('utf-8', errors='ignore'))
      for l in f:
        for m in re.finditer(r'\.html\(', l):
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cvss=self._cvss,
            title=self._summary,
            info0='{match} ({rfn})'.format(rfn=fn, match=l),
            summary=self._synopsis,
          ))

class SecurityFileWriteDetector(SignatureMixin):
  _id = 'security-file-write'
  _cvss1 = 'CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/'
  _summary1 = 'detected potential logging into file'
  _synopsis1 = 'The application is potentially logging into file.'
  _cvss2 = 'CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary2 = 'open files for writing'
  _synopsis2 = 'The application opens files for writing.'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return SecurityFileWriteDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects file creation')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.invocations(InvocationPattern('invoke-virtual', r'Landroid/content/Context;->openFileOutput\(Ljava/lang/String;I\)')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      try:
        target_val = DataFlow(q).solved_constant_data_in_invocation(cl, 0)
      except DataFlow.NoSuchValueError:
        target_val = '(unknown name)'

      if re.search(r'debug|log|info|report|screen|err|tomb|drop', target_val):
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain',
          cvss=self._cvss1,
          title=self._summary1,
          summary=self._synopsis1,
          info0=target_val,
          aff0=q.qualname_of(cl)
        ))
      else:
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain',
          cvss=self._cvss2,
          title=self._summary2,
          summary=self._synopsis2,
          info0=target_val,
          aff0=q.qualname_of(cl)
        ))

    for cl in q.invocations(InvocationPattern('invoke-direct', r'java/io/File(Writer|OutputStream)?;-><init>\(Ljava/lang/String;\)')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      try:
        target_val = DataFlow(q).solved_constant_data_in_invocation(cl, 0)

        if re.search(r'debug|log|info|report|screen|err|tomb|drop', target_val):
          if not re.search(r'^/proc/|^/sys/', target_val):
            self._helper.raise_issue(self._helper.build_issue(
              sigid=self._id,
              cfd='tentative',
              cvss=self._cvss1,
              title=self._summary1,
              summary=self._synopsis1,
              info0=target_val,
              aff0=q.qualname_of(cl)
            ))
      except DataFlow.NoSuchValueError:
        target_val = '(unknown name)'

class SecurityInsecureRootedDetector(SignatureMixin):
  _id = 'security-insecure-rooted'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  _pat_path = r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+'
  _pat_detect = r'Sup(?!p)|/su(?!pp)|xbin|sbin|root'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return SecurityInsecureRootedDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects insecure rooted device probes')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()

    attestations: Dict[str, Any] = dict()
    path_based_detection_attempt: Dict[str, Any] = dict()
    confidence: Dict[str, IssueConfidence] = dict()

    for cl in q.invocations(InvocationPattern('invoke-', r'Lcom/google/android/gms/safetynet/SafetyNetClient;->attest\(\[BLjava/lang/String;\)')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      # XXX: crude detection
      verdict_accesses = list(q.consts_in_class(cl, InvocationPattern('const-string', r'ctsProfileMatch|basicIntegrity')))
      if verdict_accesses and qn is not None:
        attestations[qn] = verdict_accesses

    for cl in q.consts(InvocationPattern('const-string', self._pat_path)):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      if qn is not None:
        attempts = self._get_attempts(cl.p[1].v)
        if attempts:
          confidence[qn] = 'firm'
          if qn not in path_based_detection_attempt:
            path_based_detection_attempt[qn] = attempts
          else:
            path_based_detection_attempt[qn].update(attempts)
    for name, val in context.string_resources():
      qn = f'R.string.{name}'
      attempts = self._get_attempts(val)
      if attempts:
        confidence[qn] = 'tentative'
        if qn not in path_based_detection_attempt:
          path_based_detection_attempt[qn] = attempts
        else:
          path_based_detection_attempt[qn].update(attempts)

    # TBD: fussy match
    for qn,vals in path_based_detection_attempt.items():
      if qn not in attestations:
        self._helper.raise_issue(self._helper.build_issue(sigid=self._id, cvss=self._cvss, title='manual root detections without remote attestations', info0=','.join(vals), aff0=qn))
    for qn,verdicts in attestations.items():
      if qn not in path_based_detection_attempt:
        self._helper.raise_issue(self._helper.build_issue(sigid=self._id, cvss=self._cvss, title='remote attestations without manual root detections', info0=','.join(verdicts), aff0=qn))

  def _get_attempts(self, x: str) -> Set[str]:
    o: Set[str] = set()
    for m in re.finditer(self._pat_path, x):
      v = m.group(0)
      if re.search(self._pat_detect, v):
        o.add(v)
    return o

class SecuritySharedPreferencesDetector(SignatureMixin):
  _id = 'security-sharedpref'
  _cvss = 'CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _summary = 'detected SharedPreference access'
  _synopsis = 'The application is using SharedPreferences. This is purely informational; Using the subsystem alone does not constitute a security issue.'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return SecuritySharedPreferencesDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects SharedPreferences access')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.invocations(InvocationPattern('invoke-interface', r'Landroid/content/SharedPreferences;->get(Boolean|Float|Int|String|StringSet)\(Ljava/lang/String;')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      try:
        target_val = DataFlow(q).solved_constant_data_in_invocation(cl, 0)
      except DataFlow.NoSuchValueError:
        target_val = '(unknown name)'

      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cfd='certain',
        cvss=self._cvss,
        title=self._summary,
        summary=self._synopsis,
        info0=target_val,
        info1='read',
        aff0=q.qualname_of(cl)
      ))

    for cl in q.invocations(InvocationPattern('invoke-interface', r'Landroid/content/SharedPreferences\$Editor;->put(Boolean|Float|Int|String|StringSet)\(Ljava/lang/String;')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      try:
        target_val = DataFlow(q).solved_constant_data_in_invocation(cl, 0)
      except DataFlow.NoSuchValueError:
        target_val = '(unknown name)'

      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cfd='certain',
        cvss=self._cvss,
        title=self._summary,
        summary=self._synopsis,
        info0=target_val,
        info1='write',
        aff0=q.qualname_of(cl)
      ))

    for cl in q.invocations(InvocationPattern('invoke-interface', r'Landroid/content/SharedPreferences/Editor;->remove\(Ljava/lang/String;')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      try:
        target_val = DataFlow(q).solved_constant_data_in_invocation(cl, 0)
      except DataFlow.NoSuchValueError:
        target_val = '(unknown name)'

      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cfd='certain',
        cvss=self._cvss,
        title=self._summary,
        summary=self._synopsis,
        info0=target_val,
        info1='delete',
        aff0=q.qualname_of(cl)
      ))
