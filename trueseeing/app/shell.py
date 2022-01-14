# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
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

from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Mapping, Type, Set
  from trueseeing.signature.base import Detector

class Signatures:
  _corpse: Mapping[str, Type[Detector]]
  def __init__(self) -> None:
    from trueseeing.signature import crypto, fingerprint, manifest, privacy, security

    sigs: List[Type[Detector]] = [
      crypto.CryptoStaticKeyDetector,
      crypto.CryptoEcbDetector,
      crypto.CryptoNonRandomXorDetector,
      fingerprint.LibraryDetector,
      fingerprint.ProGuardDetector,
      fingerprint.UrlLikeDetector,
      manifest.ManifestOpenPermissionDetector,
      manifest.ManifestMissingPermissionDetector,
      manifest.ManifestManipActivity,
      manifest.ManifestManipBroadcastReceiver,
      manifest.ManifestManipContentProvider,
      manifest.ManifestManipBackup,
      manifest.ManifestDebuggable,
      privacy.PrivacyDeviceIdDetector,
      privacy.PrivacySMSDetector,
      security.SecurityFilePermissionDetector,
      security.SecurityTlsInterceptionDetector,
      security.SecurityTamperableWebViewDetector,
      security.SecurityInsecureWebViewDetector,
      security.FormatStringDetector,
      security.LogDetector,
    ]

    self._corpse = {cl.option:cl for cl in sigs}

  def content(self) -> Mapping[str, Type[Detector]]:
    return self._corpse

  def all(self) -> Set[str]:
    return set(self._corpse.keys())

  def default(self) -> Set[str]:
    return self.all().copy()

  def selected_on(self, switch: str) -> Set[str]:
    if switch != 'all':
      if not switch.endswith('-all'):
        return set([switch])
      else:
        return {v for v in self.all() if v.startswith(switch.replace('-all', ''))}
    else:
      return self.all()


class Shell:
  @classmethod
  def _version(cls) -> str:
    from pkg_resources import get_distribution
    version = get_distribution('trueseeing').version
    return '\n'.join([
    f'Trueseeing {version}, the app vulnerability scanner',
    #.........................................................................80
    '''\
Copyright (C) 2017-22 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
All rights reserved.  Licensed under the terms of GNU General Public License Version 3 or later.'''
    ])

  @classmethod
  def _help(cls) -> str:
    return '\n'.join([
      cls._version(),
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

  @classmethod
  def _help_signatures(cls, signatures: Mapping[str, Type[Detector]]) -> str:
    return '\n'.join([
      cls._version(),
      '',
      #.........................................................................80
      'SIGNATURES',
      '',
    ] + [
      f'  {name:<36s}{signatures[name].description}' for name in sorted(signatures.keys())
    ])

  def invoke(self) -> int:
    import sys
    import getopt
    sigs = Signatures()
    log_level = ui.INFO
    signature_selected = sigs.default().copy()
    exploitation_mode = ''
    patch_mode = ''
    fingerprint_mode = False
    grab_mode = False
    inspection_mode = False
    ci_mode = 'html'

    opts, files = getopt.getopt(sys.argv[1:], 'dW:',
                                ['exploit-resign', 'exploit-unsign', 'exploit-enable-debug', 'exploit-enable-backup',
                                 'exploit-disable-pinning', 'fingerprint', 'grab', 'help', 'help-signatures', 'inspect',
                                 'output=', 'version', 'patch-all'])
    for o, a in opts:
      if o in ['-d']:
        log_level = ui.DEBUG
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
        ui.stderr(self._version())
        return 0
      if o in ['--help']:
        ui.stderr(self._help())
        return 2
      if o in ['--help-signatures']:
        ui.stderr(self._help_signatures(sigs.content()))
        return 2

    ui.level = log_level

    if grab_mode:
      from trueseeing.app.grab import GrabMode
      return GrabMode(packages=files).invoke()
    else:
      if not files:
        ui.fatal(f"no input files")
      if exploitation_mode:
        from trueseeing.app.exploit import ExploitMode
        return ExploitMode(files).invoke(exploitation_mode)
      elif patch_mode:
        from trueseeing.app.patch import PatchMode
        return PatchMode(files).invoke(patch_mode)
      elif fingerprint_mode:
        from trueseeing.app.fingerprint import FingerprintMode
        return FingerprintMode(files).invoke()
      elif inspection_mode:
        from trueseeing.app.inspect import InspectMode
        return InspectMode(files).invoke()
      else:
        from trueseeing.app.scan import ScanMode
        return ScanMode(files).invoke(
          ci_mode=ci_mode,
          signatures=[v for k, v in sigs.content().items() if k in signature_selected]
        )
