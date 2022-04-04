# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <altakey@gmail.com>
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
import asyncio

from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Type, Set, Dict, Optional, Awaitable
  from trueseeing.signature.base import Detector
  from trueseeing.core.report import ReportFormat

class Signatures:
  content: Dict[str, Type[Detector]]
  def __init__(self) -> None:
    from trueseeing.signature import crypto, fingerprint, manifest, privacy, security

    sigs: List[Type[Detector]] = [
      crypto.CryptoStaticKeyDetector,
      crypto.CryptoEcbDetector,
      crypto.CryptoNonRandomXorDetector,
      fingerprint.LibraryDetector,
      fingerprint.ProGuardDetector,
      fingerprint.UrlLikeDetector,
      fingerprint.NativeMethodDetector,
      fingerprint.NativeArchDetector,
      manifest.ManifestOpenPermissionDetector,
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
      security.ADBProbeDetector,
      security.ClientXSSJQDetector,
      security.SecurityFileWriteDetector,
      security.SecurityInsecureRootedDetector,
    ]

    self.content = {cl.option:cl for cl in sigs}

  def all(self) -> Set[str]:
    return set(self.content.keys())

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
    #   ..............................................................................80
    return (
      f'Trueseeing {version}, the app vulnerability scanner\n'
       'Copyright (C) 2017-22 Takahiro Yoshimura <altakey@gmail.com>\n' # noqa: E131
       'All rights reserved.  Licensed under the terms of GNU General Public License Version 3 or later.\n'
    )

  @classmethod
  def _help(cls) -> str:
    return '\n'.join([
      cls._version(),
      '',
      #.........................................................................80
      '''\
OPTIONS

General:
  -d/--debug                Debug mode
  --version                 Version information
  --help                    Show this text
  --help-signature          Show signatures

Scan mode:
  -W<signame>               Enable signature (use --help-signatures to list signatures)
  -Wno-<signame>            Disable signature (use --help-signatures to list signatures)
  --exclude=<pattern>       Excluding packages matching pattern
  --fingerprint             Print fingerprint
  --grab <package name>     Grab package from device
  -o/--output=<filename>    Report filename ("-" for stdout)
  --format=html|json        Report format (html: HTML (default), json: JSON)

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
  def _help_signatures(cls, signatures: Dict[str, Type[Detector]]) -> str:
    return '\n'.join([
      cls._version(),
      '',
      #.........................................................................80
      'SIGNATURES',
      '',
    ] + [
      f'  {name:<36s}{signatures[name].description}' for name in sorted(signatures.keys())
    ])

  def _launch(self, coro: Awaitable[int]) -> int:
    return asyncio.run(coro)

  def invoke(self) -> int:
    import sys
    import getopt
    from trueseeing.core.api import Extension

    sigs = Signatures()
    Extension.get().patch_signatures(sigs)

    log_level = ui.INFO
    signature_selected = sigs.default().copy()
    exploitation_mode = ''
    patch_mode = ''
    fingerprint_mode = False
    grab_mode = False
    inspection_mode = False
    output_filename: Optional[str] = None
    ci_mode: ReportFormat = 'html'
    exclude_packages: List[str] = []

    opts, files = getopt.getopt(sys.argv[1:], 'do:W:',
                                ['debug', 'exploit-resign', 'exploit-unsign', 'exploit-enable-debug', 'exploit-enable-backup',
                                 'exploit-disable-pinning', 'fingerprint', 'grab', 'help', 'help-signatures', 'inspect',
                                 'output=', 'format=', 'version', 'patch-all', 'exclude='])
    for o, a in opts:
      if o in ['-d', '--debug']:
        log_level = ui.DEBUG
        ui.is_debugging = True
      if o in ['-o', '--output']:
        output_filename = a
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
      if o in ['--exclude']:
        exclude_packages.append(a)
      if o in ['--patch-all']:
        patch_mode = 'all'
      if o in ['--grab']:
        grab_mode = True
      if o in ['--fingerprint']:
        fingerprint_mode = True
      if o in ['--inspect']:
        inspection_mode = True
      if o in ['--format']:
        # NB: should check "a" conforms to the literal type, ReportFormat
        if a in ['html', 'json']:
          ci_mode = a # type: ignore[assignment]
        else:
          ui.fatal(f'unknown output format: {a}')
      if o in ['--version']:
        ui.stderr(self._version())
        return 0
      if o in ['--help']:
        ui.stderr(self._help())
        return 2
      if o in ['--help-signatures']:
        ui.stderr(self._help_signatures(sigs.content))
        return 2

    ui.level = log_level

    if grab_mode:
      from trueseeing.app.grab import GrabMode
      return self._launch(GrabMode(packages=files).invoke())
    else:
      if not files:
        ui.fatal("no input files")
      if exploitation_mode:
        from trueseeing.app.exploit import ExploitMode
        return self._launch(ExploitMode(files).invoke(exploitation_mode))
      elif patch_mode:
        from trueseeing.app.patch import PatchMode
        return self._launch(PatchMode(files).invoke(patch_mode))
      elif fingerprint_mode:
        from trueseeing.app.fingerprint import FingerprintMode
        return self._launch(FingerprintMode(files).invoke())
      elif inspection_mode:
        from trueseeing.app.inspect import InspectMode
        return self._launch(InspectMode(files).invoke())
      else:
        from trueseeing.app.scan import ScanMode
        return self._launch(ScanMode(files).invoke(
          ci_mode=ci_mode,
          outfile=output_filename,
          signatures=[v for k, v in sigs.content.items() if k in signature_selected],
          exclude_packages=exclude_packages,
        ))
