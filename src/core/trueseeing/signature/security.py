# Vulnerabilities:
# * Security: Cross-site scripting
# * Security: Escaratable cross-site scripting (API < 17)
# * Security: Cross-site Request Forgery
# * Security: SQL injection
# * Security: Server-side JavaScript injection
# * Security: TLS interception
# * Security: Arbitrary Large-area WebView Overwrite
# * Security: Insecure permissions
# * Security: Insecure libraries
# * Security: Improper annotations
# * Security: Root introspection
# * Security: Low reverse-enginnering resistance (dex2jar+jad, androguard)

import binascii
import functools
import itertools
import lxml.etree as ET
import shutil
import re
import math
import base64
import os
import logging

from trueseeing.flow.code import InvocationPattern
from trueseeing.flow.data import DataFlows
from trueseeing.signature.base import Detector
from trueseeing.issue import IssueConfidence, Issue

log = logging.getLogger(__name__)

class SecurityFilePermissionDetector(Detector):
  option = 'security-file-permission'
  cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/'

  def do_detect(self):
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
              info1={1:'MODE_WORLD_READABLE', 2:'MODE_WORLD_WRITABLE'}[target_val],
              source=store.query().qualname_of(cl)
            )
        except (DataFlows.NoSuchValueError):
          pass

class SecurityTlsInterceptionDetector(Detector):
  option = 'security-tls-interception'
  cvss = 'CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:N/'

  def do_detect(self):
    with self.context.store() as store:
      marks = []

      pins = set()
      for m in store.query().methods_in_class('checkServerTrusted', 'X509TrustManager'):
        if any(store.query().matches_in_method(m, InvocationPattern('throw', ''))):
          pins.add(m)

      if not pins:
        yield Issue(
          detector_id=self.option,
          confidence=IssueConfidence.CERTAIN,
          cvss3_vector=self.cvss,
          summary='insecure TLS connection',
          info1='pinning X509TrustManagers are not detected'
        )
      else:
        # XXX crude detection
        for cl in self.context.store().query().invocations(InvocationPattern('invoke-virtual', 'Ljavax/net/ssl/SSLContext->init')):
          if not DataFlows.solved_typeset_in_invocation(store, cl, 2) & pins:
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.FIRM,
              cvss3_vector=self.cvss,
              summary='insecure TLS connection',
              info1='pinning X509TrustManagers are not used',
              source=store.query().qualname_of(cl)
            )
        else:
          yield Issue(
            detector_id=self.option,
            confidence=IssueConfidence.FIRM,
            cvss3_vector=self.cvss,
            summary='insecure TLS connection',
            info1='use of standard SSLContext'
          )


class LayoutSizeGuesser:
  xmlns_android = '{http://schemas.android.com/apk/res/android}'
  table = {'small':(320.0, 426.0), 'normal':(320.0, 470.0), 'large':(480.0, 640.0), 'xlarge':(720.0, 960.0)}

  def guessed_size(self, t, path):
    def dps_from_modifiers(mods):
      try:
        x, y = self.table[list(mods & self.table.keys())[0]]
      except (IndexError, KeyError):
        x, y = self.table['large']
      if 'land' in mods:
        return (y, x)
      else:
        return (x, y)

    def width_of(e):
      return e.attrib['{0}layout_width'.format(self.xmlns_android)]

    def height_of(e):
      return e.attrib['{0}layout_height'.format(self.xmlns_android)]

    def is_bound(x):
      return x not in ('fill_parent', 'match_parent', 'wrap_content')

    def guessed_dp(x, dp):
      if is_bound(x):
        try:
          return float(re.sub(r'di?p$', '', x)) / float(dp)
        except ValueError:
          log.debug("check_security_arbitrary_webview_overwrite: guessed_size: guessed_dp: warning: ignoring non-dp suffix ({!s})".format(x))
          return float(re.sub(r'[^0-9-]', '', x)) / float(dp)
      else:
        return dp

    def self_and_containers_of(e):
      yield e
      e = e.getparent()
      if e is not None:
        self_and_containers_of(e)

    def modifiers_in(path):
      return [set(c.split('-')) for c in path.split(os.sep) if 'layout' in c][0]

    dps = dps_from_modifiers(modifiers_in(path))
    for e in self_and_containers_of(t):
      if any(is_bound(x) for x in (width_of(e), height_of(e))):
        return guessed_dp(width_of(e), dps[0]) * guessed_dp(height_of(e), dps[1])
    else:
      return 1.0

class SecurityArbitraryWebViewOverwriteDetector(Detector):
  option = 'security-arbitrary-webview-overwrite'
  cvss = 'CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N/'

  xmlns_android = '{http://schemas.android.com/apk/res/android}'

  def do_detect(self):
    with self.context.store() as store:
      targets = {'WebView','XWalkView','GeckoView'}

      more = True
      while more:
        more = False
        for cl in store.query().related_classes('|'.join(targets)):
          name = store.query().class_name_of(cl)
          if name not in targets:
            targets.add(name)
            more = True

      for fn in (n for n in self.context.disassembled_resources() if 'layout' in n):
        with open(fn, 'r') as f:
          r = ET.parse(f).getroot()
          for t in functools.reduce(lambda x,y: x+y, (r.xpath('//%s' % self.context.class_name_of_dalvik_class_type(c).replace('$', '_')) for c in targets)):
            size = LayoutSizeGuesser().guessed_size(t, fn)
            if size > 0.5:
              yield Issue(
                detector_id=self.option,
                confidence=IssueConfidence.TENTATIVE,
                cvss3_vector=self.cvss,
                summary='arbitrary WebView content overwrite',
                info1='{0} (score: {1:.02f})'.format(t.attrib['{0}id'.format(self.xmlns_android)], size),
                source=self.context.source_name_of_disassembled_resource(fn)
              )

      # XXX: crude detection
      for op in store.query().invocations(InvocationPattern('invoke-', ';->loadUrl')):
        try:
          v = DataFlows.solved_constant_data_in_invocation(store, op, 0)
          if v.startswith('http://'):
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.FIRM,
              cvss3_vector=self.cvss,
              summary='arbitrary WebView content overwrite with URL',
              info1=v,
              source=store.query().qualname_of(op)
            )
        except DataFlows.NoSuchValueError:
          pass


class SecurityInsecureWebViewDetector(Detector):
  option = 'security-insecure-webview'
  cvss = 'CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H/'

  xmlns_android = '{http://schemas.android.com/apk/res/android}'

  @staticmethod
  def first(xs, default=None):
    try:
      return list(itertools.islice(xs, 1))[0]
    except IndexError:
      return default

  def do_detect(self):
    with self.context.store() as store:
      targets = {'WebView','XWalkView','GeckoView'}

      more = True
      while more:
        more = False
        for cl in store.query().related_classes('|'.join(targets)):
          name = store.query().class_name_of(cl)
          if name not in targets:
            targets.add(name)
            more = True

      # XXX: Crude detection
      for p in store.query().invocations(InvocationPattern('invoke-virtual', 'Landroid/webkit/WebSettings;->setJavaScriptEnabled')):
        try:
          if DataFlows.solved_constant_data_in_invocation(store, p, 0):
            for target in targets:
              for q in store.query().invocations_in_class(p, InvocationPattern('invoke-virtual', '%s->addJavascriptInterface' % target)):
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
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def analyzed(self, x):
    if re.search(r'%s', x):
      if re.search(r'(://|[<>/&?])', x):
        yield dict(confidence=IssueConfidence.FIRM, value=x)

  def do_detect(self):
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
            source='R.string.%s' % name
          )

class LogDetector(Detector):
  option = 'security-log'
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/'

  def do_detect(self):
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
