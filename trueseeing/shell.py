# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
import trueseeing.patch
import trueseeing.grab

from trueseeing.context import Context
from trueseeing.report import CIReportGenerator, HTMLReportGenerator, NullReporter, ProgressReporter

import pkg_resources

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

def version():
  return '\n'.join([
    'Trueseeing %s, the app vulnerability scanner' % pkg_resources.get_distribution('trueseeing').version,
    #.........................................................................80
    '''\
Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
All rights reserved.  Licensed under the terms of GNU General Public License Version 3 or later.'''
  ])

def help_():
  return '\n'.join([
    version(),
    '',
    #.........................................................................80
    '''\
OPTIONS

General:
  -d                        Debug mode
  --version                 Version information
  --help                    Show this text
  --help-signature          Show signatures

Scan mode:
  -W<signame>               Enable signature (use --help-signatures to list signatures)
  -Wno-<signame>            Disable signature (use --help-signatures to list signatures)
  --fingerprint             Print fingerprint
  --grab <package name>     Grab package from device
  --output=html|gcc         Output mode (html: HTML, gcc: Text)

Exploitation mode:
  --exploit-resign          Exploit mode: Replace signature
  --exploit-unsign          Exploit mode: Remove signature
  --exploit-enable-debug    Exploit mode: Enable debug bit
  --exploit-enable-backup   Exploit mode: Enable backup bit

Patch mode:
  --patch-all               Patch mode: apply fix

Misc:
  --inspect                 Interactive mode
'''
  ])

def help_signatures(signatures):
  return '\n'.join([
    version(),
    '',
    #.........................................................................80
    'SIGNATURES',
    '',
  ] + [
    ('  %-36s%s' % (name, signatures[name].description)) for name in sorted(signatures.keys())
  ])


def shell():
  log_level = logging.INFO
  signature_selected = signatures_default.copy()
  exploitation_mode = ''
  fingerprint_mode = False
  grab_mode = False
  inspection_mode = False
  output_format = None

  opts, files = getopt.getopt(sys.argv[1:], 'dW:', ['exploit-resign', 'exploit-unsign', 'exploit-enable-debug', 'exploit-enable-backup', 'fingerprint', 'grab', 'help', 'help-signatures', 'inspect', 'output=', 'version', 'patch-all'])
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
    if o in ['--patch-all']:
      exploitation_mode = 'patch-all'
    if o in ['--grab']:
      grab_mode = True
    if o in ['--fingerprint']:
      fingerprint_mode = True
    if o in ['--inspect']:
      inspection_mode = True
    if o in ['--output']:
      output_format = a
    if o in ['--version']:
      print(version())
      return 0
    if o in ['--help']:
      print(help_())
      return 2
    if o in ['--help-signatures']:
      print(help_signatures(signatures))
      return 2

  global preferences
  preferences = configparser.ConfigParser()
  preferences.read('.trueseeingrc')

  logging.basicConfig(level=log_level, format="%(msg)s")

  if not exploitation_mode:
    if not any([fingerprint_mode, grab_mode, inspection_mode]):
      if files:
        error_found = False
        for f in files:
          if processed(f, [v for k,v in signatures.items() if k in signature_selected], output_format=output_format):
            error_found = True
        if not error_found:
          return 0
        else:
          return 1
      else:
        print("%s: no input files" % sys.argv[0])
        return 2
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
  elif exploitation_mode == 'patch-all':
    for f in files:
      trueseeing.patch.Patches(f, os.path.basename(f).replace('.apk', '-patched.apk'), [trueseeing.patch.PatchDebuggable(), trueseeing.patch.PatchBackupable(), trueseeing.patch.PatchLoggers()]).apply()
    return 0
