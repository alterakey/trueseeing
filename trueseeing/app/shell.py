from __future__ import annotations
from typing import TYPE_CHECKING
import asyncio
import os
import sys

from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Type, Set, Dict, Optional, Coroutine, Any, Literal
  from trueseeing.signature.base import Detector
  from trueseeing.core.report import ReportFormat

  OpMode = Optional[Literal['scan', 'inspect', 'batch']]

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
      '''\
USAGE

    {me} [options ...] <target.apk>
'''.format(me=os.path.basename(sys.argv[0])),
      #.........................................................................80
      '''\
OPTIONS

General:
  -c                        Run commands before prompt
  -d/--debug                Debug mode
  -i                        Run script file before prompt
  -q                        Batch mode; quit instead of giving prompt
  --version                 Version information
  --help                    Show this text
  --help-signature          Show signatures
  --inspect                 Inspect mode (deprecated; now default)
  --scan                    Scan mode (deprecated; use -qc "aa;g*"; e.g. gh for HTML)

Scan mode (DEPRECATED):
  --scan-sigs=<sig>,..      Select signatures (use --help-signatures to list signatures)
  --scan-exclude=<pattern>  Excluding packages matching pattern
  --scan-output=<file>   Report filename ("-" for stdout)
  --scan-report=html|json   Report format (html: HTML (default), json: JSON)
  --scan-max-graph-size=<n> Set max graph size
  --scan-no-cache           Do not keep codebase cache
  --scan-update-cache       Analyze and rebuild codebase cache
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
    import getopt
    from trueseeing.core.api import Extension

    sigs = Signatures()
    Extension.get().patch_signatures(sigs)

    log_level = ui.INFO
    signature_selected = sigs.default().copy()
    mode: OpMode = None
    cmdlines = []
    no_cache_mode = False
    update_cache_mode = False
    output_filename: Optional[str] = None
    format: ReportFormat = 'html'
    exclude_packages: List[str] = []

    opts, files = getopt.getopt(sys.argv[1:], 'c:i:do:qW:',
                                ['debug',
                                 'help', 'help-signatures',
                                 'version', 'inspect',
                                 'scan', 'scan-sigs=', 'scan-output=', 'scan-report=', 'scan-exclude=', 'scan-update-cache', 'scan-no-cache', 'scan-max-graph-size='])
    for o, a in opts:
      if o in ['-d', '--debug']:
        log_level = ui.DEBUG
      if o in ['--scan-output']:
        output_filename = a
      if o in ['-q']:
        mode = 'batch'
      if o in ['-c']:
        cmdlines = [a]
      if o in ['-i']:
        try:
          with open(a, 'r') as f:
            cmdlines = [l for l in f]
        except OSError as e:
          ui.fatal(f'cannot open script file: {e}')

      if o in ['--scan-sigs']:
        for s in a.split(','):
          if s.startswith('no-'):
            signature_selected.difference_update(sigs.selected_on(s[3:]))
          else:
            signature_selected.update(sigs.selected_on(s))
      if o in ['--scan-exclude']:
        exclude_packages.append(a)
      if o in ['--inspect']:
        self._deprecated(f'{o} is deprecated; ignored as default')
      if o in ['--scan']:
        self._deprecated(f'{o} is deprecated; use -qc "aa;g*"; e.g. gh for HTML')
        mode = 'scan'
      if o in ['--scan-update-cache']:
        update_cache_mode = True
      if o in ['--scan-no-cache']:
        no_cache_mode = True
      if o in ['--scan-max-graph-size']:
        from trueseeing.core.flow.data import DataFlows
        DataFlows.set_max_graph_size(int(a))
      if o in ['--scan-report']:
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

    if not mode:
      mode = 'inspect'

    if not files:
      ui.stderr(self._help())
      return 2

    if mode in ['inspect', 'batch']:
      if len(files) > 1:
        ui.fatal(f"{mode} mode accepts at most only one target file")
      from trueseeing.app.inspect import InspectMode
      InspectMode().do(
        files[0] if files else '',
        signatures=sigs,
        batch=True if mode == 'batch' else False,
        cmdlines=cmdlines
      )
    elif mode == 'scan':
      if len(files) > 1:
        self._deprecated('specifying multiple files is deprecated')
      from trueseeing.app.scan import ScanMode
      return self._launch(ScanMode(files).invoke(
        ci_mode=format,
        outfile=output_filename,
        signatures=[v for k, v in sigs.content.items() if k in signature_selected],
        exclude_packages=exclude_packages,
        no_cache_mode=no_cache_mode,
        update_cache_mode=update_cache_mode,
      ))
    else:
      assert False, f'unknown mode: {mode}'

def entry() -> None:
  from trueseeing.core.exc import FatalError
  try:
    Shell().invoke()
  except FatalError:
    sys.exit(2)
