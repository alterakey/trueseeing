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

from trueseeing.context import warning_on
from trueseeing.flow.code import OpMatcher, InvocationPattern
from trueseeing.flow.data import DataFlows

def entropy_of(string):
  o = 0.0
  m = dict()
  for c in string:
    m[c] = m.get(c, 0) + 1
  for cnt in m.values():
    freq = float(cnt) / len(string)
    o -= freq * (math.log(freq) / math.log(2))
  return o

def assumed_randomness_of(string):
  try:
    return entropy_of(string) / float(math.log(len(string)) / math.log(2))
  except ValueError:
    return 0

def check_security_file_permission(context):
  marks = []
  for cl in context.analyzed_classes():
    for k in OpMatcher(cl.ops, InvocationPattern('invoke-virtual', 'Landroid/content/Context;->openFileOutput\(Ljava/lang/String;I\)')).matching():
      marks.append(dict(name=context.class_name_of_dalvik_class_type(cl.qualified_name()), method=k.method_, op=k))

  for m in marks:
    try:
      m['target_val'] = int(DataFlows.solved_constant_data_in_invocation(m['op'], 1), 16)
    except (DataFlows.NoSuchValueError):
      pass

  o = []
  for m in (r for r in marks if r.get('target_val', 0) & 3):
    o.append(warning_on(name=m['name'] + '#' + m['method'].v.v, row=0, col=0, desc='insecure file permission: %s' % {1:'MODE_WORLD_READABLE', 2:'MODE_WORLD_WRITABLE'}[m['target_val']], opt='-Wsecurity-file-permission'))
  return o

def check_security_tls_interception(context):
  o = []
  marks = []

  pins = set()
  for cl in context.analyzed_classes():
    # XXX crude detection
    for m in (m for m in cl.methods if re.match('checkServerTrusted', m.qualified_name())):
      for k in OpMatcher(m.ops, InvocationPattern('invoke-virtual', 'Ljava/security/MessageDigest->digest')).matching():
        pins.add(cl)
          
  if not pins:
    o.append(warning_on(name='(global)', row=0, col=0, desc='insecure TLS connection', opt='-Wsecurity-tls-interception'))
  else:
    for cl in context.analyzed_classes():
      # XXX crude detection
      for k in OpMatcher(cl.ops, InvocationPattern('invoke-virtual', 'Ljavax/net/ssl/SSLContext->init')).matching():
        if not DataFlows.solved_typeset_in_invocation(k, 2) & pins:
          o.append(warning_on(name='%s#%s' % (context.class_name_of_dalvik_class_type(cl.qualified_name()), k.method_.v.v), row=0, col=0, desc='insecure TLS connection', opt='-Wsecurity-tls-interception'))
      else:
        o.append(warning_on(name='(global)', row=0, col=0, desc='insecure TLS connection', opt='-Wsecurity-tls-interception'))
          

  return o

def check_security_arbitrary_webview_overwrite(context):
  xmlns_android = '{http://schemas.android.com/apk/res/android}'

  def dps_from_modifiers(mods):
    table = {'small':(320.0, 426.0), 'normal':(320.0, 470.0), 'large':(480.0, 640.0), 'xlarge':(720.0, 960.0)}
    try:
      x, y = table[list(mods & table.keys())[0]]
    except (IndexError, KeyError):
      x, y = table['large']
    if 'land' in mods:
      return (y, x)
    else:
      return (x, y)
  
  def guessed_size(t, dps):
    def width_of(e):
      return e.attrib['{0}layout_width'.format(xmlns_android)]
    def height_of(e):
      return e.attrib['{0}layout_height'.format(xmlns_android)]
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
    def contains(e):
      yield e
      e = e.getparent()
      if e is not None:
        contains(e)

    for e in contains(t):
      if any(is_bound(x) for x in (width_of(e), height_of(e))):
        return guessed_dp(width_of(e), dps[0]) * guessed_dp(height_of(e), dps[1])
    else:
      return 1.0  
  
  o = []

  targets = {'WebView','XWalkView','GeckoView'}
  seed = '|'.join(targets)

  more = True
  while more:
    more = False
    for cl in (c for c in context.analyzed_classes() if (c.super_.v in targets) or (re.search(seed, c.super_.v))):
      name = context.class_name_of_dalvik_class_type(cl.qualified_name())
      if name not in targets:
        targets.add(context.class_name_of_dalvik_class_type(cl.qualified_name()))
        more = True
          
  for fn in (n for n in context.disassembled_resources() if 'layout' in n):
    with open(fn, 'r') as f:
      r = ET.parse(f).getroot()
      for t in functools.reduce(lambda x,y: x+y, (r.xpath('//%s' % c.replace('$', '_')) for c in targets)):
        size = guessed_size(t, dps_from_modifiers([set(c.split('-')) for c in fn.split(os.sep) if 'layout' in c][0]))
        if size > 0.5:
          o.append(warning_on(name=context.source_name_of_disassembled_resource(fn), row=0, col=0, desc='arbitrary WebView content overwrite: {0} (score: {1:.02f})'.format(t.attrib['{0}id'.format(xmlns_android)], size), opt='-Wsecurity-arbitrary-webview-overwrite'))

  return o
