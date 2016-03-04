import os
import sys
import getopt
import configparser
import logging
import collections

import trueseeing.signature.base
import trueseeing.exploit

from trueseeing.context import Context

log = logging.getLogger(__name__)

preferences = None
signatures = collections.OrderedDict([cl.as_signature() for cl in trueseeing.signature.base.SignatureClasses().extracted()])

signatures_all = set(signatures.keys())
signatures_default = signatures_all.copy()

def formatted(issue):
  if not (issue.row is None or issue.col is None):
    return '%(source)s:%(row)d:%(col)d:%(severity)s{%(confidence)s}:%(description)s [-W%(detector_id)s]' % issue.__dict__
  else:
    return '%(source)s:0:0:%(severity)s{%(confidence)s}:%(description)s [-W%(detector_id)s]' % issue.__dict__

def processed(apkfilename, chain):
  with Context() as context:
    context.analyze(apkfilename)
    log.info("%s -> %s" % (apkfilename, context.wd))

    for c in chain:
      yield from (formatted(e) for e in c(context).detect())

def shell(argv):
  log_level = logging.INFO
  signature_selected = signatures_default.copy()
  exploitation_mode = ''

  try:
    opts, files = getopt.getopt(sys.argv[1:], 'dW:', ['exploit-resign', 'exploit-unsign'])
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
      if o in ['--exploit-resign']:
        exploitation_mode = 'resign'
      if o in ['--exploit-unsign']:
        exploitation_mode = 'unsign'
  except IndexError:
    print("%s: no input files" % argv[0])
    return 2
  else:
    global preferences
    preferences = configparser.ConfigParser()
    preferences.read('.trueseeingrc')

    logging.basicConfig(level=log_level, format="%(msg)s")

    if not exploitation_mode:
      error_found = False
      for f in files:
        for e in processed(f, [v for k,v in signatures.items() if k in signature_selected]):
          error_found = True
          print(e)
      if not error_found:
        return 0
      else:
        return 1
    elif exploitation_mode == 'resign':
      for f in files:
        trueseeing.exploit.ExploitResign(f, os.path.basename(f).replace('.apk', '-resigned.apk')).exploit()
      return 0
    elif exploitation_mode == 'unsign':
      for f in files:
        trueseeing.exploit.ExploitUnsign(f, os.path.basename(f).replace('.apk', '-unsigned.apk')).exploit()
      return 0

def entry():
  import sys
  return shell(sys.argv)
