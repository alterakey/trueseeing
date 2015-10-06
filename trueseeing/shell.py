import sys
import getopt
import itertools
import configparser
import tempfile
import os
import lxml.etree as ET
import shutil
import re
import math
import base64

preferences = None

class Context:
  def __init__(self):
    self.notes = []
    self.wd = None

  def analyze(self, apk):
    if self.wd is None:
      self.wd = tempfile.mkdtemp()
      # XXX insecure
      os.system("java -jar apktool.jar d -fo %(wd)s %(apk)s" % dict(wd=self.wd, apk=apk))
    else:
      raise ValueError('analyzed once')

  def parsed_manifest(self):
    with open(os.path.join(self.wd, 'AndroidManifest.xml'), 'r') as f:
      return ET.parse(f)

  def disassembled_classes(self):
    for root, dirs, files in os.walk(os.path.join(self.wd, 'smali')):
      yield from (os.path.join(root, f) for f in files if f.endswith('.smali'))

  def source_name_of_disassembled_class(self, fn):
    return os.path.relpath(fn, os.path.join(self.wd, 'smali'))

  def permissions_declared(self):
    yield from self.parsed_manifest().getroot().xpath('//uses-permission/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android'))

  def __enter__(self):
    return self

  def __exit__(self, *exc_details):
    shutil.rmtree(self.wd)

def warning_on(name, row, col, desc, opt):
  return dict(name=name, row=row, col=col, severity='warning', desc=desc, opt=opt)

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
  return [warning_on(name=m['name'], row=m['row'], col=m['col'], desc='insecure cryptography: static keys: %(target_key)s: "%(target_val)s"' % m, opt='-Wcrypto-static-keys') for m in marks]

def check_security_arbitrary_webview_overwrite(context):
  return [
    warning_on(name='com/gmail/altakey/ui/WebActivity.java', row=40, col=0, desc='arbitrary WebView content overwrite', opt='-Wsecurity-arbitrary-webview-overwrite'),
  ]

def check_security_dataflow_file(context):
  return [
    warning_on(name='com/gmail/altakey/model/DeviceInfo.java', row=24, col=0, desc='insecure data flow into file: IMEI/IMSI', opt='-Wsecurity-dataflow-file'),
  ]

def check_security_dataflow_wire(context):
  return [
    warning_on(name='com/gmail/altakey/api/ApiClient.java', row=48, col=0, desc='insecure data flow on wire: IMEI/IMSI', opt='-Wsecurity-dataflow-wire'),
  ]

def formatted(n):
  return '%(name)s:%(row)d:%(col)d:%(severity)s:%(desc)s [%(opt)s]' % n

def processed(apkfilename):
  with Context() as context:
    context.analyze(apkfilename)
    print("%s -> %s" % (apkfilename, context.wd))

    checker_chain = [
      check_manifest_open_permission,
      check_manifest_missing_permission,
      check_manifest_manip_activity,
      check_manifest_manip_broadcastreceiver,
      check_crypto_static_keys,
      check_security_arbitrary_webview_overwrite,
      check_security_dataflow_file,
      check_security_dataflow_wire
    ]

    for c in checker_chain:
      for e in c(context):
        yield formatted(e)

def shell(argv):
  try:
    opts, files = getopt.getopt(sys.argv[1:], 'f', [])
    for o, a in opts:
      pass

    global preferences
    preferences = configparser.ConfigParser()
    preferences.read('.trueseeingrc')

    error_found = False
    for f in files:
      for e in processed(f):
        error_found = True
        print(e)
    if not error_found:
      return 0
    else:
      return 1
  except IndexError:
    print("%s: no input files" % argv[0])
    return 2

def entry():
  import sys
  return shell(sys.argv)
