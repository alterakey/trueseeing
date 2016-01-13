import sys
import getopt
import configparser
import logging
import collections

from trueseeing.signature.fingerprint import detect_library, detect_obfuscators, detect_obfuscator_proguard, detect_urllike
from trueseeing.signature.crypto import check_crypto_static_keys, check_crypto_ecb
from trueseeing.signature.manifest import check_manifest_open_permission, check_manifest_missing_permission, check_manifest_manip_activity, check_manifest_manip_broadcastreceiver
from trueseeing.signature.privacy import check_security_dataflow_file, check_security_dataflow_wire
from trueseeing.signature.security import check_security_file_permission, check_security_tls_interception, check_security_arbitrary_webview_overwrite

from trueseeing.context import Context

log = logging.getLogger(__name__)

preferences = None
signatures = collections.OrderedDict([
  ('detect-library', detect_library),
  ('detect-obfuscator', detect_obfuscators),
  ('detect-url', detect_urllike),
  ('manifest-open-permission', check_manifest_open_permission),
  ('manifest-missing-permission', check_manifest_missing_permission),
  ('manifest-manip-activity', check_manifest_manip_activity),
  ('manifest-manip-broadcastreceiver', check_manifest_manip_broadcastreceiver),
  ('crypto-static-keys', check_crypto_static_keys),
  ('crypto-ecb', check_crypto_ecb),
  ('security-file-permission', check_security_file_permission),
  ('security-tls-interception', check_security_tls_interception),
  ('security-arbitrary-webview-overwrite', check_security_arbitrary_webview_overwrite),
  ('security-dataflow-file', check_security_dataflow_file),
  ('security-dataflow-wire', check_security_dataflow_wire),
])

signatures_all = set(signatures.keys())
signatures_default = signatures_all.copy()

def formatted(n):
  return '%(name)s:%(row)d:%(col)d:%(severity)s:%(desc)s [%(opt)s]' % n

def processed(apkfilename, chain):
  with Context() as context:
    context.analyze(apkfilename)
    log.info("%s -> %s" % (apkfilename, context.wd))

    for c in chain:
      yield from (formatted(e) for e in c(context))

def shell(argv):
  log_level = logging.INFO
  signature_selected = signatures_default.copy()
  
  try:
    opts, files = getopt.getopt(sys.argv[1:], 'dW:', [])
    for o, a in opts:
      if o in ['-d']:
        log_level = logging.DEBUG
      if o in ['-W']:
        if a.startswith('no-'):
          target = a[3:]
          if target != 'all':
            try:
              signature_selected.remove(a[3:])
            except KeyError:
              pass
          else:
            signature_selected.clear()
        else:
          target = a
          if target != 'all':
            signature_selected.add(target)
          else:
            signature_selected.update(signatures_all)
  except IndexError:
    print("%s: no input files" % argv[0])
    return 2
  else:
    global preferences
    preferences = configparser.ConfigParser()
    preferences.read('.trueseeingrc')

    logging.basicConfig(level=log_level, format="%(msg)s")

    error_found = False
    for f in files:
      for e in processed(f, [v for k,v in signatures.items() if k in signature_selected]):
        error_found = True
        print(e)
    if not error_found:
      return 0
    else:
      return 1

def entry():
  import sys
  return shell(sys.argv)
