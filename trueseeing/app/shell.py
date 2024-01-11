from __future__ import annotations
from typing import TYPE_CHECKING
import asyncio

from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Type, Set, Dict, Optional, Coroutine, Any, Literal
  from trueseeing.signature.base import Detector
  from trueseeing.core.report import ReportFormat

  OpMode = Optional[Literal['grab', 'exploit', 'patch', 'fingerprint', 'scan', 'inspect']]

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
      manifest.ManifestCleartextPermitted,
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
      security.SecuritySharedPreferencesDetector,
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
    from trueseeing import __version__
    #   ..............................................................................80
    return (
      f'Trueseeing {__version__}, the app vulnerability scanner\n'
       'Copyright (C) Takahiro Yoshimura <altakey@gmail.com> et al.\n' # noqa: E131
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
  --scan                    Scan mode
  --scan-sigs=<sig>,..      Select signatures (use --help-signatures to list signatures)
  --scan-exclude=<pattern>  Excluding packages matching pattern
  -o/--scan-output=<file>   Report filename ("-" for stdout)
  --scan-report=html|json   Report format (html: HTML (default), json: JSON)

Inspect mode:
  --inspect                 Inspect mode

Misc:
  --update-cache            Analyze and rebuild codebase cache
  --no-cache                Do not keep codebase cache
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

  def _launch(self, coro: Coroutine[Any, Any, int]) -> int:
    return asyncio.run(coro)

  def _deprecated(self, msg: str) -> None:
    ui.warn(f'warning: {msg}', onetime=True)

  def invoke(self) -> int:
    import sys
    import getopt
    from trueseeing.core.api import Extension

    sigs = Signatures()
    Extension.get().patch_signatures(sigs)

    log_level = ui.INFO
    signature_selected = sigs.default().copy()
    mode: OpMode = None
    exploit = ''
    patch = ''
    no_cache_mode = False
    update_cache_mode = False
    output_filename: Optional[str] = None
    format: ReportFormat = 'html'
    exclude_packages: List[str] = []

    opts, files = getopt.getopt(sys.argv[1:], 'do:W:',
                                ['debug', 'exploit-resign', 'exploit-unsign', 'exploit-enable-debug', 'exploit-enable-backup',
                                 'exploit-disable-pinning', 'fingerprint', 'grab', 'help', 'help-signatures',
                                 'output=', 'format=', 'version', 'patch-all', 'exclude=', 'update-cache', 'no-cache', 'inspect', 'max-graph-size=',
                                 'scan', 'scan-sigs=', 'scan-output=', 'scan-report=', 'scan-exclude='])
    for o, a in opts:
      if o in ['-d', '--debug']:
        log_level = ui.DEBUG
      if o == '--output':
        self._deprecated(f'{o} is deprecated (use --scan-output)')
      if o in ['-o', '--output']:
        output_filename = a
      if o in ['-W']:
        self._deprecated('-W<sig>/-Wno-<sig> is deprecated (use --scan-sigs)')
        if a.startswith('no-'):
          signature_selected.difference_update(sigs.selected_on(a[3:]))
        else:
          signature_selected.update(sigs.selected_on(a))
      if o in ['--scan-sigs']:
        for s in a.split(','):
          if s.startswith('no-'):
            signature_selected.difference_update(sigs.selected_on(s[3:]))
          else:
            signature_selected.update(sigs.selected_on(s))
      if o in ['--exploit-resign']:
        self._deprecated(f'{o} is deprecated')
        mode = 'exploit'
        exploit = 'resign'
      if o in ['--exploit-unsign']:
        self._deprecated(f'{o} is deprecated')
        mode = 'exploit'
        exploit = 'unsign'
      if o in ['--exploit-enable-debug']:
        self._deprecated(f'{o} is deprecated (try xd in inspect mode)')
        mode = 'exploit'
        exploit = 'enable-debug'
      if o in ['--exploit-enable-backup']:
        self._deprecated(f'{o} is deprecated (try xb in inspect mode)')
        mode = 'exploit'
        exploit = 'enable-backup'
      if o in ['--exploit-disable-pinning']:
        self._deprecated(f'{o} is deprecated (try xu in inspect mode)')
        mode = 'exploit'
        exploit = 'disable-pinning'
      if o == '--exclude':
        self._deprecated(f'{o} is deprecated (use --scan-exclude)')
      if o in ['--scan-exclude', '--exclude']:
        exclude_packages.append(a)
      if o in ['--patch-all']:
        self._deprecated(f'{o} is deprecated')
        mode = 'patch'
        patch = 'all'
      if o in ['--update-cache']:
        update_cache_mode = True
      if o in ['--no-cache']:
        no_cache_mode = True
      if o in ['--grab']:
        self._deprecated(f'{o} is deprecated')
        mode = 'grab'
      if o in ['--fingerprint']:
        self._deprecated(f'{o} is deprecated (try i in inspect mode)')
        mode = 'fingerprint'
      if o in ['--inspect']:
        mode = 'inspect'
      if o in ['--scan']:
        mode = 'scan'
      if o in ['--max-graph-size']:
        from trueseeing.core.flow.data import DataFlows
        DataFlows.set_max_graph_size(int(a))
      if o == '--format':
        self._deprecated(f'{o} is deprecated (use --scan-report)')
      if o in ['--scan-report', '--format']:
        # NB: should check "a" conforms to the literal type, ReportFormat
        if a in ['html', 'json']:
          format = a # type: ignore[assignment]
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

    ui.set_level(log_level)

    if not files and not mode:
      mode = 'inspect'

    if mode == 'grab':
      from trueseeing.app.grab import GrabMode
      return self._launch(GrabMode(packages=files).invoke())
    elif mode == 'inspect':
      if len(files) > 1:
        ui.fatal("inspect mode accepts at most only one target file")
      from trueseeing.app.inspect import InspectMode
      InspectMode().do(files[0] if files else '', signatures=sigs)
    else:
      if not files:
        ui.fatal("no input files")
      if len(files) > 1:
        self._deprecated('specifying multiple files is deprecated')
      if mode == 'exploit':
        from trueseeing.app.exploit import ExploitMode
        return self._launch(ExploitMode(files).invoke(
          exploit,
          no_cache_mode=no_cache_mode
        ))
      elif mode == 'patch':
        from trueseeing.app.patch import PatchMode
        return self._launch(PatchMode(files).invoke(
          patch,
          no_cache_mode=no_cache_mode
        ))
      elif mode == 'fingerprint':
        from trueseeing.app.fingerprint import FingerprintMode
        return self._launch(FingerprintMode(files).invoke())
      else:
        from trueseeing.app.scan import ScanMode
        if not mode:
          self._deprecated('implicit scan mode is deprecated (specify --scan)')
        return self._launch(ScanMode(files).invoke(
          ci_mode=format,
          outfile=output_filename,
          signatures=[v for k, v in sigs.content.items() if k in signature_selected],
          exclude_packages=exclude_packages,
          no_cache_mode=no_cache_mode,
          update_cache_mode=update_cache_mode,
        ))
