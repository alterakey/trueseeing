import os
import sys
import getopt
import configparser
import logging
import resource
import collections
import tempfile
import datetime

import trueseeing.signature.base
import trueseeing.exploit
import trueseeing.grab

from trueseeing.context import Context
from trueseeing.report import CIReportGenerator, HTMLReportGenerator, NullReporter, ProgressReporter
from trueseeing.shell import processed

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

def shell():
  log_level = logging.INFO
  signature_selected = signatures_default.copy()
  exploitation_mode = ''
  fingerprint_mode = False
  grab_mode = False
  output_format = None
  api_cputime_limit = None
  api_read_limit = None
  api_expires = None

  opts, files = getopt.getopt(sys.argv[1:], 'dW:', ['exploit-resign', 'exploit-unsign', 'exploit-enable-debug', 'exploit-enable-backup', 'fingerprint', 'grab', 'inspect', 'output=', 'rlimit-cpu=', 'rlimit-input=', 'rlimit-expires=', 'api'])
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
    if o in ['--output']:
      output_format = a
    if o in ['--rlimit-cpu']:
      api_cputime_limit = int(a)
      resource.setrlimit(resource.RLIMIT_CPU, (api_cputime_limit, api_cputime_limit))
    if o in ['--rlimit-input']:
      api_read_limit = int(a)
    if o in ['--rlimit-expires']:
      api_expires = datetime.datetime.fromtimestamp(int(a))

  global preferences
  preferences = configparser.ConfigParser()
  preferences.read('.trueseeingrc')

  logging.basicConfig(level=log_level, format="%(msg)s")

  if api_expires is not None:
    if api_expires < datetime.datetime.today():
      sys.stderr.write('Your license is expired\n')
      return 1

  sys.stderr.write('Trueseeing 2.0.1, the app vulnerability scanner\n')
  sys.stderr.write('Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>.  All rights reserved.\n')
  if api_cputime_limit is not None:
    sys.stderr.write('Maximum CPU time is %s\n' % ('%.02f sec' % api_cputime_limit))
  if api_read_limit is not None:
    sys.stderr.write('Maximum input filesize: %s\n' % ('%d bytes' % api_read_limit))
  if api_expires is not None:
    sys.stderr.write('Expires at: %s\n' % (api_expires.date().isoformat()))
  sys.stderr.flush()
  with tempfile.NamedTemporaryFile('w+b') as f:
    if api_read_limit is not None:
      f.write(sys.stdin.buffer.read(api_read_limit))
    else:
      f.write(sys.stdin.buffer.read())
    f.seek(0)
    if fingerprint_mode:
      print('%s: %s' % (f.name, Context().fingerprint_of(f)))
    else:
      processed(f.name, [v for k,v in signatures.items() if k in signature_selected], output_format=output_format)
    return 0
