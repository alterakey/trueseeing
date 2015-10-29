import sys
import getopt
import configparser

from trueseeing import fingerprint, signatures
from trueseeing.context import Context

preferences = None


def formatted(n):
  return '%(name)s:%(row)d:%(col)d:%(severity)s:%(desc)s [%(opt)s]' % n

def processed(apkfilename):
  with Context() as context:
    context.analyze(apkfilename)
    print("%s -> %s" % (apkfilename, context.wd))

    checker_chain = [
      fingerprint.detect_library,
      fingerprint.detect_obfuscators,
      signatures.check_manifest_open_permission,
      signatures.check_manifest_missing_permission,
      signatures.check_manifest_manip_activity,
      signatures.check_manifest_manip_broadcastreceiver,
      signatures.check_crypto_static_keys,
      signatures.check_security_arbitrary_webview_overwrite,
      signatures.check_security_dataflow_file,
      signatures.check_security_dataflow_wire
    ]

    for c in checker_chain:
      for e in c(context):
        yield formatted(e)

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
