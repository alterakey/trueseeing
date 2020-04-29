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

import sys
import getopt
import logging
import collections

import trueseeing.signature.base
from trueseeing.app.exploit import ExploitMode
from trueseeing.app.fingerprint import FingerprintMode
from trueseeing.app.grab import GrabMode
from trueseeing.app.inspect import InspectMode
from trueseeing.app.patch import PatchMode
from trueseeing.app.scan import ScanMode

import pkg_resources

log = logging.getLogger(__name__)

class Signatures:
  def __init__(self):
    self._corpse = collections.OrderedDict(
      [cl.as_signature() for cl in trueseeing.signature.base.SignatureClasses().extracted()]
    )

  def content(self):
    return self._corpse

  def all(self):
    return set(self._corpse.keys())

  def default(self):
    return self.all().copy()

  def selected_on(self, switch):
    if switch != 'all':
      if not switch.endswith('-all'):
        return set([switch])
      else:
        return {v for v in self.all() if v.startswith(switch.replace('-all', ''))}
    else:
      return self.all()


class Shell:
  @staticmethod
  def version():
    return '\n'.join([
    'Trueseeing %s, the app vulnerability scanner' % pkg_resources.get_distribution('trueseeing').version,
    #.........................................................................80
    '''\
Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
All rights reserved.  Licensed under the terms of GNU General Public License Version 3 or later.'''
    ])

  @staticmethod
  def help_():
    return '\n'.join([
      Shell.version(),
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
  --output=html|gcc|json    Output mode (html: HTML, gcc: Text, json: JSON)

Exploitation mode:
  --exploit-resign          Exploit mode: Replace signature
  --exploit-unsign          Exploit mode: Remove signature
  --exploit-enable-debug    Exploit mode: Enable debug bit
  --exploit-enable-backup   Exploit mode: Enable backup bit
  --exploit-disable-pinning Exploit mode: Disable TLS Pinning (>=API 24)

Patch mode:
  --patch-all               Patch mode: apply fix

Misc:
  --inspect                 Interactive mode
'''
    ])

  @staticmethod
  def help_signatures(signatures):
    return '\n'.join([
      Shell.version(),
      '',
      #.........................................................................80
      'SIGNATURES',
      '',
    ] + [
      ('  %-36s%s' % (name, signatures[name].description)) for name in sorted(signatures.keys())
    ])

  def invoke(self):
    sigs = Signatures()
    log_level = logging.INFO
    signature_selected = sigs.default().copy()
    exploitation_mode = ''
    patch_mode = ''
    fingerprint_mode = False
    grab_mode = False
    inspection_mode = False
    ci_mode = False

    opts, files = getopt.getopt(sys.argv[1:], 'dW:',
                                ['exploit-resign', 'exploit-unsign', 'exploit-enable-debug', 'exploit-enable-backup',
                                 'exploit-disable-pinning', 'fingerprint', 'grab', 'help', 'help-signatures', 'inspect',
                                 'output=', 'version', 'patch-all'])
    for o, a in opts:
      if o in ['-d']:
        log_level = logging.DEBUG
      if o in ['-W']:
        if a.startswith('no-'):
          signature_selected.difference_update(sigs.selected_on(a[3:]))
        else:
          signature_selected.update(sigs.selected_on(a))

      if o in ['--exploit-resign']:
        exploitation_mode = 'resign'
      if o in ['--exploit-unsign']:
        exploitation_mode = 'unsign'
      if o in ['--exploit-enable-debug']:
        exploitation_mode = 'enable-debug'
      if o in ['--exploit-enable-backup']:
        exploitation_mode = 'enable-backup'
      if o in ['--exploit-disable-pinning']:
        exploitation_mode = 'disable-pinning'
      if o in ['--patch-all']:
        patch_mode = 'all'
      if o in ['--grab']:
        grab_mode = True
      if o in ['--fingerprint']:
        fingerprint_mode = True
      if o in ['--inspect']:
        inspection_mode = True
      if o in ['--output']:
        ci_mode = a
      if o in ['--version']:
        print(Shell.version())
        return 0
      if o in ['--help']:
        print(Shell.help_())
        return 2
      if o in ['--help-signatures']:
        print(Shell.help_signatures(sigs.content()))
        return 2

    logging.basicConfig(level=log_level, format="%(msg)s")

    if exploitation_mode:
      return ExploitMode(files).invoke(exploitation_mode)
    elif patch_mode:
      return PatchMode(files).invoke(patch_mode)
    elif fingerprint_mode:
      return FingerprintMode(files).invoke()
    elif grab_mode:
      return GrabMode(packages=files).invoke()
    elif inspection_mode:
      return InspectMode(files).invoke()
    else:
      return ScanMode(files).invoke(
        ci_mode=ci_mode,
        signatures=[v for k, v in sigs.content().items() if k in signature_selected]
      )