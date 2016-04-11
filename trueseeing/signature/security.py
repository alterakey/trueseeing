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

from trueseeing.flow.code import OpMatcher, InvocationPattern
from trueseeing.flow.data import DataFlows
from trueseeing.signature.base import Detector, IssueSeverity, IssueConfidence

log = logging.getLogger(__name__)

class SecurityFilePermissionDetector(Detector):
  option = 'security-file-permission'
  
  def do_detect(self):
    for cl in self.context.analyzed_classes():
      for k in OpMatcher(cl.ops, InvocationPattern('invoke-virtual', 'Landroid/content/Context;->openFileOutput\(Ljava/lang/String;I\)')).matching():
        try:
          target_val = int(DataFlows.solved_constant_data_in_invocation(k, 1), 16)
          if target_val & 3:
            yield self.issue(IssueSeverity.SEVERE, IssueConfidence.CERTAIN, '%(name)s#%(method)s' % dict(name=self.context.class_name_of_dalvik_class_type(cl.qualified_name()), method=k.method_.v.v), 'insecure file permission: %s' % {1:'MODE_WORLD_READABLE', 2:'MODE_WORLD_WRITABLE'}[target_val])
        except (DataFlows.NoSuchValueError):
          pass

class SecurityTlsInterceptionDetector(Detector):
  option = 'security-tls-interception'
  
  def do_detect(self):
    marks = []

    pins = set()
    for cl in self.context.analyzed_classes():
      # XXX crude detection
      for m in (m for m in cl.methods if re.match('checkServerTrusted', m.qualified_name())):
        for k in OpMatcher(m.ops, InvocationPattern('invoke-virtual', 'Ljava/security/MessageDigest->digest')).matching():
          pins.add(cl)

    if not pins:
      yield self.issue(IssueSeverity.MEDIUM, IssueConfidence.CERTAIN, '(global)', 'insecure TLS connection')
    else:
      for cl in self.context.analyzed_classes():
        # XXX crude detection
        for k in OpMatcher(cl.ops, InvocationPattern('invoke-virtual', 'Ljavax/net/ssl/SSLContext->init')).matching():
          if not DataFlows.solved_typeset_in_invocation(k, 2) & pins:
            yield self.issue(IssueSeverity.MEDIUM, IssueConfidence.FIRM, '%s#%s' % (self.context.class_name_of_dalvik_class_type(cl.qualified_name()), k.method_.v.v), 'insecure TLS connection')
        else:
          yield self.issue(IssueSeverity.MEDIUM, IssueConfidence.FIRM, '(global)', 'insecure TLS connection')


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
          return int(re.sub(r'di?p$', '', x)) / float(dp)
        except ValueError:
          print("check_security_arbitrary_webview_overwrite: guessed_size: guessed_dp: warning: ignoring non-dp suffix ({!s})".format(x))
          return int(re.sub(r'[^0-9-]', '', x)) / float(dp)
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
  
  xmlns_android = '{http://schemas.android.com/apk/res/android}'
  
  def do_detect(self):
    targets = {'WebView','XWalkView','GeckoView'}
    seed = '|'.join(targets)

    more = True
    while more:
      more = False
      for cl in (c for c in self.context.analyzed_classes() if (c.super_.v in targets) or (re.search(seed, c.super_.v))):
        name = self.context.class_name_of_dalvik_class_type(cl.qualified_name())
        if name not in targets:
          targets.add(self.context.class_name_of_dalvik_class_type(cl.qualified_name()))
          more = True

    for fn in (n for n in self.context.disassembled_resources() if 'layout' in n):
      with open(fn, 'r') as f:
        r = ET.parse(f).getroot()
        for t in functools.reduce(lambda x,y: x+y, (r.xpath('//%s' % c.replace('$', '_')) for c in targets)):
          size = LayoutSizeGuesser().guessed_size(t, fn)
          if size > 0.5:
            yield self.issue(IssueSeverity.MEDIUM, IssueConfidence.TENTATIVE, self.context.source_name_of_disassembled_resource(fn), 'arbitrary WebView content overwrite: {0} (score: {1:.02f})'.format(t.attrib['{0}id'.format(self.xmlns_android)], size))

class SecurityInsecureWebViewDetector(Detector):
  option = 'security-insecure-webview'

  xmlns_android = '{http://schemas.android.com/apk/res/android}'

  @staticmethod
  def first(xs, default=None):
    try:
      return list(itertools.islice(xs, 1))[0]
    except IndexError:
      return default

  def do_detect(self):
    targets = {'WebView','XWalkView','GeckoView'}
    seed = '|'.join(targets)

    more = True
    while more:
      more = False
      for cl in (c for c in self.context.analyzed_classes() if (c.super_.v in targets) or (re.search(seed, c.super_.v))):
        name = self.context.class_name_of_dalvik_class_type(cl.qualified_name())
        if name not in targets:
          targets.add(self.context.class_name_of_dalvik_class_type(cl.qualified_name()))
          more = True

    # XXX: Crude detection
    for cl in self.context.analyzed_classes():
      p = self.first(OpMatcher(cl.ops, InvocationPattern('invoke-virtual', 'Landroid/webkit/WebSettings;->setJavaScriptEnabled')).matching())
      try:
        if p and DataFlows.solved_constant_data_in_invocation(p, 0):
          for target in targets:
            q = self.first(OpMatcher(cl.ops, InvocationPattern('invoke-virtual', 'L(%s);->addJavascriptInterface' % target)).matching())
            if q:
              try:
                if DataFlows.solved_constant_data_in_invocation(q, 0):
                  yield self.issue(IssueSeverity.MAJOR, IssueConfidence.FIRM, '%s#%s' % (self.context.class_name_of_dalvik_class_type(cl.qualified_name()), q.method_.v.v), 'insecure Javascript interface')
              except (DataFlows.NoSuchValueError):
                yield self.issue(IssueSeverity.MAJOR, IssueConfidence.TENTATIVE, '%s#%s' % (self.context.class_name_of_dalvik_class_type(cl.qualified_name()), q.method_.v.v), 'insecure Javascript interface')
      except (DataFlows.NoSuchValueError):
        pass

class FormatStringDetector(Detector):
  option = 'security-format-string'

  def analyzed(self, x):
    if re.search(r'%s', x):
      if re.search(r'(://|[<>/&?])', x):
        yield dict(severity=IssueSeverity.INFO, confidence=IssueConfidence.FIRM, value=x)

  def do_detect(self):
    for cl in self.context.analyzed_classes():
      for k in OpMatcher(cl.ops, InvocationPattern('const-string', '.')).matching():
        for t in self.analyzed(k.p[1].v):
          yield self.issue(t['severity'], t['confidence'], '%(name)s#%(method)s' % dict(name=self.context.class_name_of_dalvik_class_type(cl.qualified_name()), method=k.method_.v.v), 'detected format string: %(target_val)s' % dict(target_val=t['value']))
    for name, val in self.context.string_resources():
      for t in self.analyzed(val):
        yield self.issue(t['severity'], t['confidence'], 'R.string.%s' % name, 'detected format string: %(target_val)s' % dict(target_val=t['value']))
