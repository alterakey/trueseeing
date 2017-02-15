import os
import sys
import getopt
import configparser
import logging
import collections

import trueseeing.signature.base
import trueseeing.exploit
import trueseeing.grab

from trueseeing.context import Context
from trueseeing.report import CIReportGenerator, HTMLReportGenerator, APIHTMLReportGenerator, NullReporter, ProgressReporter

log = logging.getLogger(__name__)

preferences = None
signatures = collections.OrderedDict([cl.as_signature() for cl in trueseeing.signature.base.SignatureClasses().extracted()])

signatures_all = set(signatures.keys())
signatures_default = signatures_all.copy()

def processed(apkfilename, chain, output_format=None):
  with Context() as context:
    context.analyze(apkfilename)
    log.info("%s -> %s" % (apkfilename, context.wd))
    with context.store().db as db:
      db.execute('delete from analysis_issues')

    found = False
    sigs_done = 0
    sigs_total = len(chain)

    if output_format == 'gcc':
      reporter = CIReportGenerator(context)
    elif output_format == 'api':
      reporter = APIHTMLReportGenerator(context, NullReporter())
    else:
      reporter = HTMLReportGenerator(context, ProgressReporter(sigs_total))

    for c in chain:
      with context.store().db as db:
        for e in c(context).detect():
          found = True
          reporter.note(e)
          db.execute('insert into analysis_issues (detector, summary, synopsis, description, seealso, solution, info1, info2, info3, confidence, cvss3_score, cvss3_vector, source, row, col) values (:detector_id, :summary, :synopsis, :description, :seealso, :solution, :info1, :info2, :info3, :confidence, :cvss3_score, :cvss3_vector, :source, :row, :col)', e.__dict__)
        else:
          reporter.progress().progress()
    else:
      reporter.generate()
    return reporter.return_(found)

def selected_signatures_on(switch):
  if switch != 'all':
    if not switch.endswith('-all'):
      return set([switch])
    else:
      return {v for v in signatures_all if v.startswith(switch.replace('-all', ''))}
  else:
    return signatures_all

def shell(argv):
  log_level = logging.INFO
  signature_selected = signatures_default.copy()
  exploitation_mode = ''
  fingerprint_mode = False
  grab_mode = False
  inspection_mode = False
  output_format = None

  try:
    opts, files = getopt.getopt(sys.argv[1:], 'dW:', ['exploit-resign', 'exploit-unsign', 'exploit-enable-debug', 'exploit-enable-backup', 'fingerprint', 'grab', 'inspect', 'output='])
    for o, a in opts:
      if o in ['-d']:
        log_level = logging.DEBUG
      if o in ['-W']:
        if a.startswith('no-'):
          signature_selected.difference_update(selected_signatures_on(a[3:]))
        else:
          signature_selected.update(selected_signatures_on(a))

      if o in ['--exploit-resign']:
        exploitation_mode = 'resign'
      if o in ['--exploit-unsign']:
        exploitation_mode = 'unsign'
      if o in ['--exploit-enable-debug']:
        exploitation_mode = 'enable-debug'
      if o in ['--exploit-enable-backup']:
        exploitation_mode = 'enable-backup'
      if o in ['--grab']:
        grab_mode = True
      if o in ['--fingerprint']:
        fingerprint_mode = True
      if o in ['--inspect']:
        inspection_mode = True
      if o in ['--output']:
        output_format = a
  except IndexError:
    print("%s: no input files" % argv[0])
    return 2
  else:
    global preferences
    preferences = configparser.ConfigParser()
    preferences.read('.trueseeingrc')

    logging.basicConfig(level=log_level, format="%(msg)s")

    if not exploitation_mode:
      if not any([fingerprint_mode, grab_mode, inspection_mode]):
        error_found = False
        for f in files:
          if processed(f, [v for k,v in signatures.items() if k in signature_selected], output_format=output_format):
            error_found = True
        if not error_found:
          return 0
        else:
          return 1
      elif fingerprint_mode:
        for f in files:
          print('%s: %s' % (f, Context().fingerprint_of(f)))
      elif grab_mode:
        if files:
          for pkg in files:
            if trueseeing.grab.Grab(pkg).exploit():
              print('%s: package saved: %s.apk' % (sys.argv[0], pkg))
              return 0
            else:
              print('%s: package not found' % sys.argv[0])
              return 1
        else:
          print('%s: listing packages' % sys.argv[0])
          for p in sorted(trueseeing.grab.Grab(None).list_()):
            print(p)
          return 0
      elif inspection_mode:
        f = files[0]
        with Context() as context:
          print("inspection mode; analyzing %s" % f)
          context.analyze(f)
          print("analyzed, context in 'context'")
          from IPython import embed
          embed()
    elif exploitation_mode == 'resign':
      for f in files:
        trueseeing.exploit.ExploitResign(f, os.path.basename(f).replace('.apk', '-resigned.apk')).exploit()
      return 0
    elif exploitation_mode == 'unsign':
      for f in files:
        trueseeing.exploit.ExploitUnsign(f, os.path.basename(f).replace('.apk', '-unsigned.apk')).exploit()
      return 0
    elif exploitation_mode == 'enable-debug':
      for f in files:
        trueseeing.exploit.ExploitEnableDebug(f, os.path.basename(f).replace('.apk', '-debuggable.apk')).exploit()
      return 0
    elif exploitation_mode == 'enable-backup':
      for f in files:
        trueseeing.exploit.ExploitEnableBackup(f, os.path.basename(f).replace('.apk', '-backupable.apk')).exploit()
      return 0

def entry():
  import sys
  return shell(sys.argv)
