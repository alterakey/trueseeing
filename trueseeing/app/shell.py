from __future__ import annotations
from typing import TYPE_CHECKING
import asyncio
import sys

from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Optional, Coroutine, Any, Literal

  OpMode = Optional[Literal['scan', 'inspect', 'batch']]

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

  def _launch(self, coro: Coroutine[Any, Any, int]) -> int:
    return asyncio.run(coro)

  def _deprecated(self, msg: str) -> None:
    ui.warn(f'warning: {msg}', onetime=True)

  def invoke(self) -> int:
    from argparse import ArgumentParser
    from trueseeing.core.ext import Extension

    log_level = ui.INFO
    cmdlines = []

    parser = ArgumentParser(description='Non-decompiling Android app vulnerability scanner')
    args_mut0 = parser.add_mutually_exclusive_group()
    args_mut1 = parser.add_mutually_exclusive_group()
    parser.add_argument('fn', nargs='?', metavar='FILE', help='Target APK file')
    parser.add_argument('--help-signatures', action='store_true', help='Show signatures')
    parser.add_argument('--version', action='store_true', help='Version information')
    parser.add_argument('--norc', action='store_true', help='Ignore startup file')
    parser.add_argument('--noext', action='store_true', help='Ignore extensions')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug mode')
    parser.add_argument('-e', '--abort-on-errors', action='store_true', help='Abort on errors')
    parser.add_argument('-n', dest='no_target', action='store_true', help='Open empty file')
    args_mut0.add_argument('-i', dest='scriptfn', metavar='FILE', help='Run script file before prompt')
    args_mut0.add_argument('-c', dest='inline_cmd', metavar='COMMAND', help='Run commands before prompt')
    args_mut1.add_argument('-q', dest='mode', action='store_const', const='batch', help='Batch mode; quit instead of giving prompt')
    args_mut1.add_argument('--inspect', dest='mode', action='store_const', const='inspect', help='Inspect mode (deprecated; now default)')
    args_mut1.add_argument('--scan', dest='mode', action='store_const', const='scan', help='Scan mode (deprecated; use -eqc "as;g*"; e.g. gh for HTML)')

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
    if args.noext:
      ui.warn('disabling extensions')
      Extension.disabled = True

    if not args.mode:
      args.mode = 'inspect'
    elif args.mode == 'inspect':
      self._deprecated('--inspect is deprecated; ignored as default')
    elif args.mode == 'scan':
      self._deprecated('--scan is deprecated; use -eqc "as;g*"; e.g. gh for HTML')
    if args.inline_cmd:
      cmdlines = [args.inline_cmd]
    if args.scriptfn:
      try:
        with open(args.scriptfn, 'r') as f:
          cmdlines = [l for l in f]
      except OSError as e:
        ui.fatal(f'cannot open script file: {e}')
    if args.scan_max_graph_size:
      from trueseeing.core.android.analysis.flow import DataFlow
      DataFlow.set_max_graph_size(args.scan_max_graph_size)
    if args.version:
      ui.stderr(self._version())
      return 0
    if args.help_signatures:
      args.no_target = True
      args.mode = 'batch'
      cmdlines = ['?s?']

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
        batch=True if args.mode == 'batch' else False,
        cmdlines=cmdlines,
        abort_on_errors=args.abort_on_errors,
      )
    elif args.mode == 'scan':
      from trueseeing.core.exc import InvalidFileFormatError
      try:
        from trueseeing.app.scan import ScanMode
        app = ScanMode(
          args.fn,
          outform=args.scan_report_format,
          outfile=args.scan_output_filename,
          sigsels=args.scan_sigs.split(',') if args.scan_sigs else [],
          excludes=args.scan_exclude_packages if args.scan_exclude_packages else [],
        )
        if args.scan_update_cache:
          return self._launch(app.reanalyze())
        else:
          return self._launch(app.scan(oneshot=args.scan_no_cache))
      except InvalidFileFormatError:
        ui.fatal('cannot recognize format')
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
