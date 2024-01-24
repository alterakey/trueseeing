from __future__ import annotations
from typing import TYPE_CHECKING
import asyncio
import os
import sys

from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Type, Set, Dict, Optional, Coroutine, Any, Literal
  from trueseeing.signature.base import Detector

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
      fingerprint.ReflectionDetector,
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
      f'Trueseeing {__version__}, an non-decompiling Android app vulnerability scanner\n'
       'Copyright (C) Takahiro Yoshimura <altakey@gmail.com> et al.\n' # noqa: E131
       'All rights reserved.  Licensed under the terms of GNU General Public License Version 3 or later.\n'
    )

  @classmethod
  def _help(cls) -> str:
    return '\n'.join([
      cls._version(),
      '''\
USAGE

    {me} [options ...] [<target.apk>]
'''.format(me=os.path.basename(sys.argv[0])),
      #.........................................................................80
      '''\
OPTIONS

General:
  -c                        Run commands before prompt
  -d/--debug                Debug mode
  -i                        Run script file before prompt
  -n                        Open empty file
  -q                        Batch mode; quit instead of giving prompt
  --version                 Version information
  --help                    Show this text
  --help-signature          Show signatures
  --inspect                 Inspect mode (deprecated; now default)
  --scan                    Scan mode (deprecated; use -qc "as;g*"; e.g. gh for HTML)

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
      'signatures:',
    ] + [
      f'  {name:<36s}{signatures[name].description}' for name in sorted(signatures.keys())
    ])

  def _launch(self, coro: Coroutine[Any, Any, int]) -> int:
    return asyncio.run(coro)

  def _deprecated(self, msg: str) -> None:
    ui.warn(f'warning: {msg}', onetime=True)

  def invoke(self) -> int:
    from argparse import ArgumentParser
    from trueseeing.core.api import Extension

    sigs = Signatures()
    Extension.get().patch_signatures(sigs)

    log_level = ui.INFO
    signature_selected = sigs.default().copy()
    cmdlines = []

    parser = ArgumentParser(description='Non-decompiling Android app vulnerability scanner')
    args_mut0 = parser.add_mutually_exclusive_group()
    args_mut1 = parser.add_mutually_exclusive_group()
    parser.add_argument('fn', nargs='?', metavar='FILE', help='Target APK file')
    parser.add_argument('--help-signatures', action='store_true', help='Show signatures')
    parser.add_argument('--version', action='store_true', help='Version information')
    parser.add_argument('--norc', action='store_true', help='Ignore startup file')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug mode')
    parser.add_argument('-n', dest='no_target', action='store_true', help='Open empty file')
    args_mut0.add_argument('-i', dest='scriptfn', metavar='FILE', help='Run script file before prompt')
    args_mut0.add_argument('-c', dest='inline_cmd', metavar='COMMAND', help='Run commands before prompt')
    args_mut1.add_argument('-q', dest='mode', action='store_const', const='batch', help='Batch mode; quit instead of giving prompt')
    args_mut1.add_argument('--inspect', dest='mode', action='store_const', const='inspect', help='Inspect mode (deprecated; now default)')
    args_mut1.add_argument('--scan', dest='mode', action='store_const', const='scan', help='Scan mode (deprecated; use -qc "as;g*"; e.g. gh for HTML)')

    scan_args = parser.add_argument_group('Scan mode (DEPRECATED)')
    scan_args.add_argument('--scan-sigs', metavar='SIG,...', help='Select signatures (use --help-signatures to list signatures)')
    scan_args.add_argument('--scan-exclude', dest='scan_exclude_packages', action='append', metavar='PATTERN', help='Excluding packages matching pattern')
    scan_args.add_argument('--scan-output', dest='scan_output_filename', metavar='FILE', help='Report filename ("-" for stdout)')
    scan_args.add_argument('--scan-report', dest='scan_report_format', choices=['html', 'json'], help='Report format (html: HTML (default), json: JSON)')
    scan_args.add_argument('--scan-max-graph-size', type=int, metavar='N', help='Limit graph size')
    scan_args_mut = scan_args.add_mutually_exclusive_group()
    scan_args_mut.add_argument('--scan-update-cache', action='store_true', help='Analyze and rebuild codebase cache')
    scan_args_mut.add_argument('--scan-no-cache', action='store_true', help='Do not keep codebase cache')
    args = parser.parse_args()

    if args.debug:
      log_level = ui.DEBUG
    if not args.mode:
      args.mode = 'inspect'
    elif args.mode == 'inspect':
      self._deprecated('--inspect is deprecated; ignored as default')
    elif args.mode == 'scan':
      self._deprecated('--scan is deprecated; use -qc "as;g*"; e.g. gh for HTML')
    if args.inline_cmd:
      cmdlines = [args.inline_cmd]
    if args.scriptfn:
      try:
        with open(args.scriptfn, 'r') as f:
          cmdlines = [l for l in f]
      except OSError as e:
        ui.fatal(f'cannot open script file: {e}')
    if args.scan_sigs:
      for s in args.scan_sigs.split(','):
        if s.startswith('no-'):
          signature_selected.difference_update(sigs.selected_on(s[3:]))
        else:
          signature_selected.update(sigs.selected_on(s))
    if args.scan_max_graph_size:
      from trueseeing.core.flow.data import DataFlows
      DataFlows.set_max_graph_size(args.scan_max_graph_size)
    if args.version:
      ui.stderr(self._version())
      return 0
    if args.help_signatures:
      ui.stderr(self._help_signatures(sigs.content))
      return 2

    ui.set_level(log_level)

    if not args.fn:
      if args.no_target:
        args.fn = '/dev/null'
      else:
        parser.print_help()
        return 2

    if args.mode in ['inspect', 'batch']:
      from trueseeing.app.inspect import InspectMode

      if not args.norc:
        from trueseeing.core.env import get_rc_path
        try:
          with open(get_rc_path(), 'r') as f:
            rc = [l for l in f]
          cmdlines = rc + cmdlines
        except FileNotFoundError:
          pass
        except OSError as e:
          ui.warn(f'cannot open rc file, ignoring: {e}')

      InspectMode().do(
        args.fn,
        signatures=sigs,
        batch=True if args.mode == 'batch' else False,
        cmdlines=cmdlines,
      )
    elif args.mode == 'scan':
      from trueseeing.app.scan import ScanMode
      return self._launch(ScanMode([args.fn]).invoke(
        ci_mode=args.scan_report_format,
        outfile=args.scan_output_filename,
        signatures=[v for k, v in sigs.content.items() if k in signature_selected],
        exclude_packages=args.scan_exclude_packages if args.scan_exclude_packages else [],
        no_cache_mode=args.scan_no_cache,
        update_cache_mode=args.scan_update_cache,
      ))
    else:
      assert False, f'unknown mode: {args.mode}'

def entry() -> None:
  from trueseeing.core.exc import FatalError
  try:
    _require_platform()
    Shell().invoke()
  except FatalError:
    sys.exit(2)

def _require_platform() -> None:
  import sys
  val = sys.platform
  if val == 'win32':
    ui.fatal(f'platform not supported: {val} (consider using containers)')
