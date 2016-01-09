import sys
import getopt
import configparser

from trueseeing.signature.fingerprint import detect_library, detect_obfuscators, detect_obfuscator_proguard, detect_urllike
from trueseeing.signature.crypto import check_crypto_static_keys, check_crypto_ecb
from trueseeing.signature.manifest import check_manifest_open_permission, check_manifest_missing_permission, check_manifest_manip_activity, check_manifest_manip_broadcastreceiver
from trueseeing.signature.privacy import check_security_dataflow_file, check_security_dataflow_wire
from trueseeing.signature.security import check_security_file_permission, check_security_tls_interception, check_security_arbitrary_webview_overwrite

from trueseeing.context import Context

preferences = None


def formatted(n):
  return '%(name)s:%(row)d:%(col)d:%(severity)s:%(desc)s [%(opt)s]' % n

def processed(apkfilename):
  with Context() as context:
    context.analyze(apkfilename)
    print("%s -> %s" % (apkfilename, context.wd))

    checker_chain = [
      detect_library,
      detect_obfuscators,
      detect_urllike,
      check_manifest_open_permission,
      check_manifest_missing_permission,
      check_manifest_manip_activity,
      check_manifest_manip_broadcastreceiver,
      check_crypto_static_keys,
      check_crypto_ecb,
      check_security_file_permission,
      check_security_tls_interception,
      check_security_arbitrary_webview_overwrite,
      check_security_dataflow_file,
      check_security_dataflow_wire
    ]

    for c in checker_chain:
      yield from (formatted(e) for e in c(context))

def shell(argv):
  try:
    opts, files = getopt.getopt(sys.argv[1:], 'f', [])
    for o, a in opts:
      pass
  except IndexError:
    print("%s: no input files" % argv[0])
    return 2
  else:
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

def entry():
  import sys
  return shell(sys.argv)
