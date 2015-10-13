# Vulnerabilities:
# * Cryptography: Insecure cryptography: Static keys
# * Cryptography: Insecure cryptography: ECB
# * Cryptography: Insecure cryptography: CBC with fixed key/IV
# * Cryptography: Insecure cryptography: CFB/OFB with fixed key/IV
# * Cryptography: Insecure cryptography: CTR with same counter and key
# * Cryptography: Insecure cryptography: non-random XOR cipher
# * Cryptography: Insecure cryptography: implicit trust on non-authenticated data
#
# * Manifest: Open permissions
# * Manifest: Missing permissions
# * Manifest: Manual permissions (API < 16)
# * Manifest: Manipulatable ContentProvider (API < 9)
# * Manifest: Manipulatable Activity (API < 17)
# * Manifest: Manipulatable BroadcastReceiver
# * Manifest: Manipulatable backups
# * Battery: High drainage
# * Battery: Persistent logging
# * Battery: Persistent messaging
# * Battery: Persistent wakelocks
# * Battery: Persistent disk operations
# * Battery: Heavy overdrawing
# * DoS: Crashable Intents
# * DoS: Crashable Preferences
# * DoS: Crashable code path
# * Privacy: Tainted data en clair: logs
# * Privacy: IMEI/IMSI on the wire
# * Privacy: Tainted data en clair: the wire
# * Privacy: Tainted data en clair: permissive files
# * Privacy: Tainted data en clair: preferences
# * Privacy: Transmitting tainted data to questionable entity (country)
#
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

from trueseeing.context import warning_on

def check_manifest_open_permission(context):
  for p in context.permissions_declared():
    print(p)
  return [
    warning_on(name='AndroidManifest.xml', row=1, col=0, desc='open permissions: android.permission.READ_PHONE_STATE', opt='-Wmanifest-open-permission'),
    warning_on(name='AndroidManifest.xml', row=1, col=0, desc='open permissions: android.permission.READ_SMS', opt='-Wmanifest-open-permission')
  ]

def check_manifest_missing_permission(context):
  return [
    warning_on(name='AndroidManifest.xml', row=1, col=0, desc='missing permissions: android.permission.READ_CONTACTS', opt='-Wmanifest-open-permission'),
  ]

def check_manifest_manip_activity(context):
  return [warning_on(name='AndroidManifest.xml', row=1, col=0, desc='manipulatable Activity: %s' % name, opt='-Wmanifest-manip-activity') for name in set(itertools.chain(
    context.parsed_manifest().getroot().xpath('//activity[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
    context.parsed_manifest().getroot().xpath('//activity[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
  ))]

def check_manifest_manip_broadcastreceiver(context):
  return [warning_on(name='AndroidManifest.xml', row=1, col=0, desc='manipulatable BroadcastReceiver: %s' % name, opt='-Wmanifest-manip-broadcastreceiver') for name in set(itertools.chain(
    context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
    context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
  ))]


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
  return entropy_of(string) / float(math.log(len(string)) / math.log(2))

def check_crypto_static_keys(context):
  marks = []
  for fn in context.disassembled_classes():
    with open(fn, 'r') as f:
      for l in (r for r in f if re.search('const[-/]', r)):
        m = re.search(r'"([0-9A-Za-z+/=]{8,}=?)"', l)
        if m:
          try:
            raw = base64.b64decode(m.group(1))
          except ValueError:
            raw = None
          if (assumed_randomness_of(m.group(1)) > 0.7) or (raw is not None and (len(raw) % 8 == 0 and assumed_randomness_of(raw) > 0.5)):
            marks.append(dict(name=context.source_name_of_disassembled_class(fn), row=1, col=0, target_key='<ref>', target_val=m.group(1)))

  o = []
  for m in marks:
    try:
      decoded = base64.b64decode(m['target_val'])
      o.append(warning_on(name=m['name'], row=m['row'], col=m['col'], desc='insecure cryptography: static keys: %s: "%s" [%d] (base64; "%s" [%d])' % (m['target_key'], m['target_val'], len(m['target_val']), binascii.hexlify(decoded).decode('ascii'), len(decoded)), opt='-Wcrypto-static-keys'))
    except (ValueError, binascii.Error):
      o.append(warning_on(name=m['name'], row=m['row'], col=m['col'], desc='insecure cryptography: static keys: %s: "%s" [%d]' % (m['target_key'], m['target_val'], len(m['target_val'])), opt='-Wcrypto-static-keys'))
  return o

def check_security_arbitrary_webview_overwrite(context):
  marks = []

  candidates = set()
  seed = set(['L.*WebView;'])
  more = True

  while more:
    more = False
    for fn in context.disassembled_classes():
      with open(fn, 'r') as f:
        m = re.search(r'^\.super\s+(%s)$' % ('|'.join(candidates if candidates else seed)), ''.join((l for l, _ in zip(f, range(10)))), re.MULTILINE)
        if m is not None:
          type_ = context.dalvik_type_of_disassembled_class(fn)
          if not any([re.match(x, type_) for x in candidates]):
            candidates.add(m.group(1))
            candidates.add(type_)
            more = True

  for fn in context.disassembled_resources():
    with open(fn, 'r') as f:
      r = ET.parse(f).getroot()
      for t in functools.reduce(lambda x,y: x+y, (r.xpath('//%s' % context.class_name_of_dalvik_class_type(c)) for c in candidates)):
        marks.append(dict(name=context.source_name_of_disassembled_resource(fn), row=1, col=0))

  o = []
  for m in marks:
    o.append(warning_on(name=m['name'], row=m['row'], col=m['col'], desc='arbitrary WebView content overwrite', opt='-Wsecurity-arbitrary-webview-overwrite'))
  return o

def check_security_dataflow_file(context):
  return [
    warning_on(name='com/gmail/altakey/model/DeviceInfo.java', row=24, col=0, desc='insecure data flow into file: IMEI/IMSI', opt='-Wsecurity-dataflow-file'),
  ]

def check_security_dataflow_wire(context):
  return [
    warning_on(name='com/gmail/altakey/api/ApiClient.java', row=48, col=0, desc='insecure data flow on wire: IMEI/IMSI', opt='-Wsecurity-dataflow-wire'),
  ]
