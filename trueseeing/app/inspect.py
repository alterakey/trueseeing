from __future__ import annotations
from collections import deque
import asyncio
from contextlib import contextmanager
import shlex
import sys
import re
from typing import TYPE_CHECKING

from trueseeing.core.ui import ui
from trueseeing.core.exc import FatalError

if TYPE_CHECKING:
  from typing import Mapping, Optional, Any, NoReturn, List, Type, Tuple, Iterator
  from trueseeing.signature.base import Detector
  from trueseeing.app.shell import Signatures
  from trueseeing.core.context import Context

class InspectMode:
  def do(
      self,
      target: Optional[str],
      signatures: Signatures
  ) -> NoReturn:
    try:
      ui.enter_inspect()
      self._do(target, signatures)
    finally:
      ui.exit_inspect()

  def _do(
      self,
      target: Optional[str],
      signatures: Signatures
  ) -> NoReturn:
    from code import InteractiveConsole

    sein = self
    runner = Runner(signatures, target)

    asyncio.run(runner.greeting())

    class LambdaConsole(InteractiveConsole):
      def runsource(self, source: str, filename: Optional[str]=None, symbol: Optional[str]=None) -> bool:
        try:
          asyncio.run(sein._worker(runner.run(source)))
        except FatalError:
          pass
        return False

    try:
      import readline
    except ImportError:
      readline = None # type: ignore[assignment] # noqa: F841
    ps1, ps2 = getattr(sys, 'ps1', None), getattr(sys, 'ps2', None)
    try:
      runner.reset_prompt()
      LambdaConsole(locals=locals(), filename='<input>').interact(banner='', exitmsg='')
      sys.exit(0)
    finally:
      sys.ps1, sys.ps2 = ps1, ps2

  async def _worker(self, coro: Any) -> None:
    tasks = [asyncio.create_task(coro)]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
      t.cancel()
    if pending:
      _, _ = await asyncio.wait(pending)
    for t in done:
      if not t.cancelled():
        x = t.exception()
        if x and not isinstance(x, FatalError):
          assert isinstance(x, Exception)
          ui.fatal('unhandled exception', exc=x)

class Runner:
  _cmds: Mapping[str, Mapping[str, Any]]
  _quiet: bool = False
  _verbose: bool = False
  _target: Optional[str]
  _sigs: Signatures

  def __init__(self, signatures: Signatures, target: Optional[str]) -> None:
    self._sigs = signatures
    self._target = target
    self._cmds = {
      '?':dict(e=self._help, n='?', d='help'),
      '?@?':dict(e=self._help_mod, n='?@?', d='modifier help'),
      '?o?':dict(e=self._help_opt, n='?o?', d='options help'),
      '?s?':dict(e=self._help_signature, n='?s?', d='signature help'),
      '!':dict(e=self._shell, n='!', d='shell'),
      'a':dict(e=self._analyze, n='a[!]', d='analyze target'),
      'a!':dict(e=self._analyze),
      'aa':dict(e=self._analyze2, n='aa[!]', d='analyze and scan'),
      'aa!':dict(e=self._analyze2),
      'as':dict(e=self._scan, n='as', d='run a scan'),
      'co':dict(e=self._export_context, n='co[!] /path', d='export codebase'),
      'co!':dict(e=self._export_context),
      'cf':dict(e=self._use_framework, n='cf framework.apk', d='use framework'),
      'ca':dict(e=self._assemble, n='ca[!] /path', d='assemble as target from path'),
      'ca!':dict(e=self._assemble),
      'cd':dict(e=self._disassemble, n='cd[s][!] /path', d='disassemble target into path'),
      'cd!':dict(e=self._disassemble),
      'cds':dict(e=self._disassemble),
      'cds!':dict(e=self._disassemble),
      'xq':dict(e=self._exploit_discard, n='xq', d='exploit: discard changes'),
      'xx':dict(e=self._exploit_apply, n='xx[!]', d='exploit: apply and rebuild apk'),
      'xx!':dict(e=self._exploit_apply),
      #'xf':dict(e=self._exploit_inject, n='xf', d='exploit; inject frida gadget'),
      'xu':dict(e=self._exploit_disable_pinning, n='xu', d='exploit: disable SSL/TLS pinning'),
      'xd':dict(e=self._exploit_enable_debug, n='xd', d='exploit: make debuggable'),
      'xb':dict(e=self._exploit_enable_backup, n='xb', d='exploit: make backupable'),
      'xt':dict(e=self._exploit_patch_target_api_level, n='xt[!] <api level>', d='exploit: patch target api level'),
      'xt!':dict(e=self._exploit_patch_target_api_level),
      'xp':dict(e=self._exploit_device_list_packages, n='xp', d='device: list installed packages'),
      'xco':dict(e=self._exploit_device_copyout, n='xco[!] package [data.tar]', d='device: copy-out package data'),
      'xco!':dict(e=self._exploit_device_copyout),
      'xci':dict(e=self._exploit_device_copyin, n='xci[!] package [data.tar]', d='device: copy-in package data'),
      'xci!':dict(e=self._exploit_device_copyin),
      'i':dict(e=self._info, n='i', d='print general information'),
      'gh':dict(e=self._report_html, n='gh[!] [report.html]', d='generate report (HTML)'),
      'gh!':dict(e=self._report_html),
      'gj':dict(e=self._report_json, n='gj[!] [report.json]', d='generate report (JSON)'),
      'gj!':dict(e=self._report_json),
      'gt':dict(e=self._report_text, n='gt[!] [report.txt]', d='generate report (text)'),
      'gt!':dict(e=self._report_text),
      'o':dict(e=self._set_target, n='o target.apk', d='set target APK'),
      'pf':dict(e=self._show_file, n='pf[x][!] path [output.bin]', d='show file (x: hex)'),
      'pf!':dict(e=self._show_file),
      'pfx':dict(e=self._show_file),
      'pfx!':dict(e=self._show_file),
      'pd':dict(e=self._show_disasm, n='pd[!] class [output.smali]', d='show disassembled class'),
      'pd!':dict(e=self._show_disasm),
      'pk':dict(e=self._show_solved_constant, n='pk op index', d='guess and show what constant would flow into the index-th arg of op (!: try harder)'),
      'pt':dict(e=self._show_solved_typeset, n='pt op index', d='guess and show what type would flow into the index-th arg of op'),
      '/c':dict(e=self._search_call, n='/c [pat]', d='search call for pattern'),
      '/k':dict(e=self._search_const, n='/k insn [pat]', d='search consts for pattern'),
      '/p':dict(e=self._search_put, n='/p[i] [pat]', d='search s/iputs for pattern'),
      '/dp':dict(e=self._search_defined_package, n='/dp [pat]', d='search packages matching pattern'),
      '/dc':dict(e=self._search_defined_class, n='/dc [pat]', d='search classes defined in packages matching pattern'),
      '/dcx':dict(e=self._search_derived_class, n='/dcx class [pat]', d='search classes extending ones matching pattern'),
      '/dci':dict(e=self._search_implementing_class, n='/dci interface [pat]', d='search classes implementing interfaces matching pattern'),
      '/dm':dict(e=self._search_defined_method, n='/dm class [pat]', d='search classes defining methods matching pattern'),
      '/f':dict(e=self._search_file, n='/f [pat]', d='search files those names matching pattern'),
      '/s':dict(e=self._search_string, n='/s pat', d='search files for string'),
    }

  def _get_modifiers(self, args: deque[str]) -> List[str]:
    o = []
    for m in args:
      if m.startswith('@'):
        o.append(m)
    return o

  def _get_effective_options(self, mods: List[str]) -> Mapping[str, str]:
    o = {}
    for m in mods:
      if m.startswith('@o:'):
        for a in m[3:].split(','):
          c: List[str] = a.split('=', maxsplit=1)
          if len(c) == 1:
            o[c[0]] = c[0]
          else:
            o[c[0]] = c[1]
    return o

  def _get_effective_sigs(self, mods: List[str]) -> List[Type[Detector]]:
    signature_selected = self._sigs.default().copy()
    for m in mods:
      if m.startswith('@s:'):
        for a in m[3:].split(','):
          if a.startswith('no-'):
            signature_selected.difference_update(self._sigs.selected_on(a[3:]))
          else:
            signature_selected.update(self._sigs.selected_on(a))
    return [v for k, v in self._sigs.content.items() if k in signature_selected]

  def _get_graph_size_limit(self, mods: List[str]) -> Optional[int]:
    for m in mods:
      if m.startswith('@gs:'):
        c = m[4:]
        s = re.search(r'[km]$', c.lower())
        if s:
          return int(m[4:-1]) * dict(k=1024, m=1024*1024)[s.group(0)]
        else:
          return int(m[4:])
    return None

  def get_target(self) -> Optional[str]:
    return self._target

  async def greeting(self) -> None:
    from trueseeing import __version__ as version
    ui.success(f"Trueseeing {version} [inspect mode]")

  async def run(self, s: str) -> None:
    try:
      tokens = deque(shlex.split(s))
      if not tokens:
        return

      c = tokens[0]
      if c not in self._cmds:
        ui.error('invalid command, type ? for help')
      else:
        try:
          ent: Any = self._cmds[c]['e']
          try:
            await ent(tokens)
          except KeyboardInterrupt:
            ui.fatal('interrupted')
        except FatalError:
          pass
    finally:
      self._reset_loglevel()
      self.reset_prompt()

  def _reset_loglevel(self, debug:bool = False) -> None:
    ui.set_level(ui.INFO)

  def reset_prompt(self) -> None:
    if self._target:
      sys.ps1, sys.ps2 = ui.colored(f'ts[{self.get_target()}]> ', color='yellow'), ui.colored('... ', color='yellow')
    else:
      sys.ps1, sys.ps2 = ui.colored('ts> ', color='yellow'), ui.colored('... ', color='yellow')

  async def _help(self, args: deque[str]) -> None:
    ui.success('Commands:')
    width = (2 + max([len(e.get('d', '')) for e in self._cmds.values()]) // 4) * 4
    for c in sorted(self._cmds):
      e = self._cmds[c]
      if 'n' in e:
        ui.stderr(
          f'{{n:<{width}s}}{{d}}'.format(n=e['n'], d=e['d'])
        )

  async def _help_signature(self, args: deque[str]) -> None:
    ui.success('Signatures:')
    sigs = self._sigs.content
    width = 2 + max([len(k) for k in sigs.keys()])
    for k in sorted(sigs.keys()):
      ui.stderr(
        f'{{n:<{width}s}}{{d}}'.format(n=k, d=sigs[k].description)
      )

  async def _help_mod(self, args: deque[str]) -> None:
    from trueseeing.core.flow.data import DataFlows
    ui.success('Modifiers:')
    mods = {
      '@s:sig':'include sig',
      '@x:pa.ckage.name':'exclude package',
      '@o:option': 'pass option',
      '@gs:<int>[kmKM]': 'set graph size limit (currently {})'.format(DataFlows.get_max_graph_size()),
    }

    width = 2 + max([len(k) for k in mods.keys()])
    for k in sorted(mods.keys()):
      ui.stderr(
        f'{{n:<{width}s}}{{d}}'.format(n=k, d=mods[k])
      )

  async def _help_opt(self, args: deque[str]) -> None:
    ui.success('Options:')
    mods = {
      'nocache':'do not replicate content before build [ca]',
    }

    width = 2 + max([len(k) for k in mods.keys()])
    for k in sorted(mods.keys()):
      ui.stderr(
        f'{{n:<{width}s}}{{d}}'.format(n=k, d=mods[k])
      )

  def _require_target(self, msg: Optional[str] = None) -> None:
    if self._target is None:
      ui.fatal(msg if msg else 'need target')

  @contextmanager
  def _apply_graph_size_limit(self, l: Optional[int]) -> Iterator[None]:
    from trueseeing.core.flow.data import DataFlows
    try:
      if l is not None:
        ui.info('using graph size limit: {} nodes'.format(l))
      o = DataFlows.set_max_graph_size(l)
      yield None
    finally:
      DataFlows.set_max_graph_size(o)

  async def _analyze(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    cmd = args.popleft()
    apk = self._target

    ui.info(f"analyzing {apk}")

    from trueseeing.core.context import Context
    with Context(apk, []) as context:
      if cmd.endswith('!'):
        context.remove()
      await context.analyze()
      with context.store().db as db:
        db.execute('delete from analysis_issues')

  async def _analyze2(self, args: deque[str]) -> None:
    await self._analyze(args)
    await self._scan(args)

  async def _shell(self, args: deque[str]) -> None:
    from asyncio import create_subprocess_shell
    await (await create_subprocess_shell('sh', shell=True)).wait()

  async def _scan(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    apk = self._target

    limit = self._get_graph_size_limit(self._get_modifiers(args))

    import time
    from trueseeing.app.scan import ScanMode
    from trueseeing.core.context import Context

    with self._apply_graph_size_limit(limit):
      at = time.time()
      await ScanMode([apk]).invoke(
        ci_mode='html',
        outfile=None,
        signatures=self._get_effective_sigs(self._get_modifiers(args)),
        exclude_packages=[],
        no_cache_mode=False,
        update_cache_mode=False,
        from_inspect_mode=True,
      )
      with Context(apk, []) as context:
        with context.store().db as db:
          for nr, in db.execute('select count(1) from analysis_issues'):
            ui.success("done, found {nr} issues ({t:.02f} sec.)".format(nr=nr, t=(time.time() - at)))

  async def _show_file(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._require_target()
    assert self._target is not None

    cmd = args.popleft()

    if not args:
      ui.fatal('need path')

    path = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from binascii import hexlify
    from trueseeing.core.context import Context
    with Context(self._target, []) as context:
      with context.store().db as db:
        for d, in db.execute('select blob from files where path like :path', dict(path=path)):
          if outfn is None:
            sys.stdout.buffer.write(d if 'x' not in cmd else hexlify(d))
          else:
            with open(outfn, 'wb') as f:
              f.write(d if 'x' not in cmd else hexlify(d))

  async def _show_disasm(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._require_target()
    assert self._target is not None

    cmd = args.popleft()

    if not args:
      ui.fatal('need class')

    class_ = args.popleft()

    import os

    if args:
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.context import Context
    with Context(self._target, []) as context:
      store = context.store()
      path = '{}.smali'.format(os.path.join(*(class_.split('.'))))
      with store.db as db:
        for d, in db.execute('select blob from files where path like :path', dict(path=f'smali%/{path}')):
          if outfn is None:
            sys.stdout.buffer.write(d)
          else:
            with open(outfn, 'wb') as f:
              f.write(d)

  async def _show_solved_constant(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    cmd = args.popleft()
    apk = self._target

    if len(args) < 2:
      ui.fatal('need op and index')

    opn = int(args.popleft())
    idx = int(args.popleft())

    limit = self._get_graph_size_limit(self._get_modifiers(args))

    from trueseeing.core.context import Context
    from trueseeing.core.flow.data import DataFlows
    with self._apply_graph_size_limit(limit):
      with Context(apk, []) as context:
        await context.analyze()
        store = context.store()
        op = store.op_get(opn)
        if op is not None:
          if cmd.endswith('!'):
            vs = DataFlows.solved_possible_constant_data_in_invocation(store, op, idx)
            ui.info(repr(vs))
          else:
            try:
              v = DataFlows.solved_constant_data_in_invocation(store, op, idx)
              ui.info(repr(v))
            except DataFlows.NoSuchValueError as e:
              ui.error(str(e))
        else:
          ui.error('op #{} not found'.format(opn))

  async def _show_solved_typeset(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if len(args) < 2:
      ui.fatal('need op and index')

    opn = int(args.popleft())
    idx = int(args.popleft())

    limit = self._get_graph_size_limit(self._get_modifiers(args))

    from trueseeing.core.context import Context
    from trueseeing.core.flow.data import DataFlows
    with self._apply_graph_size_limit(limit):
      with Context(apk, []) as context:
        await context.analyze()
        store = context.store()
        op = store.op_get(opn)
        if op is not None:
          vs = DataFlows.solved_typeset_in_invocation(store, op, idx)
          ui.info(repr(vs))
        else:
          ui.error('op #{} not found'.format(opn))

  async def _report_html(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._require_target()
    assert self._target is not None

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.context import Context
    from trueseeing.core.report import HTMLReportGenerator
    with Context(self._target, []) as context:
      gen = HTMLReportGenerator(context)
      if outfn is None:
        from io import StringIO
        f0 = StringIO()
        gen.generate(f0)
        ui.stdout(f0.getvalue())
      else:
        with open(outfn, 'w') as f1:
          gen.generate(f1)

  async def _report_json(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._require_target()
    assert self._target is not None

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.context import Context
    from trueseeing.core.report import JSONReportGenerator
    with Context(self._target, []) as context:
      gen = JSONReportGenerator(context)
      if outfn is None:
        from io import StringIO
        f0 = StringIO()
        gen.generate(f0)
        ui.stdout(f0.getvalue())
      else:
        with open(outfn, 'w') as f1:
          gen.generate(f1)

  async def _report_text(self, args: deque[str]) -> None:
    outfn: Optional[str] = None

    self._require_target()
    assert self._target is not None

    cmd = args.popleft()

    if args:
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    from trueseeing.core.context import Context
    from trueseeing.core.report import CIReportGenerator
    with Context(self._target, []) as context:
      gen = CIReportGenerator(context)
      if outfn is None:
        from io import StringIO
        f0 = StringIO()
        gen.generate(f0)
        ui.stdout(f0.getvalue())
      else:
        with open(outfn, 'w') as f1:
          gen.generate(f1)

  async def _search_file(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    from trueseeing.core.context import Context
    with Context(apk, []) as context:
      await context.analyze()
      store = context.store()
      for path, in store.db.execute('select path from files where path regexp :pat', dict(pat=pat)):
        ui.info(f'{path}')

  async def _search_string(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if not args:
      ui.fatal('need pattern')

    pat = args.popleft()

    ui.info('searching in files: {pat}'.format(pat=pat))

    from trueseeing.core.context import Context
    with Context(apk, []) as context:
      await context.analyze()
      store = context.store()
      for path, in store.db.execute('select path from files where blob regexp :pat', dict(pat=pat.encode('latin1'))):
        ui.info(f'{path}')

  async def _search_call(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if not args:
      ui.fatal('need pattern')

    pat = args.popleft()

    from trueseeing.core.context import Context
    from trueseeing.core.code.model import InvocationPattern
    with Context(apk, []) as context:
      await context.analyze()
      store = context.store()
      for op in store.query().invocations(InvocationPattern('invoke-', pat)):
        qn = store.query().qualname_of(op)
        ui.info(f'{qn}: {op}')

  async def _search_const(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if not args:
      ui.fatal('need insn')

    insn = args.popleft()
    if args:
      pat = args.popleft()
    else:
      pat = '.'

    from trueseeing.core.context import Context
    from trueseeing.core.code.model import InvocationPattern
    with Context(apk, []) as context:
      await context.analyze()
      store = context.store()
      for op in store.query().consts(InvocationPattern(insn, pat)):
        qn = store.query().qualname_of(op)
        ui.info(f'{qn}: {op}')

  async def _search_put(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    cmd = args.popleft()
    apk = self._target

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    from trueseeing.core.context import Context
    with Context(apk, []) as context:
      await context.analyze()
      store = context.store()
      if not cmd.endswith('i'):
        fun = store.query().sputs
      else:
        fun = store.query().iputs

      for op in fun(pat):
        qn = store.query().qualname_of(op)
        ui.info(f'{qn}: {op}')

  async def _search_defined_package(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if args:
      pat = args.popleft()
    else:
      pat = '.'

    import os
    from trueseeing.core.context import Context
    with Context(apk, []) as context:
      await context.analyze()
      packages = set()
      for fn in (context.source_name_of_disassembled_class(r) for r in context.disassembled_classes()):
        if fn.endswith('.smali'):
          packages.add(os.path.dirname(fn))
      for pkg in sorted(packages):
        if re.match(pat, pkg):
          ui.info(pkg)

  async def _search_defined_class(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if not args:
      ui.fatal('need pattern')

    pat = args.popleft()

    from trueseeing.core.context import Context
    with Context(apk, []) as context:
      await context.analyze()
      store = context.store()
      for op in store.query().classes_in_package_named(pat):
        cn = store.query().class_name_of(op)
        ui.info(f'{cn}: {op}')

  async def _search_derived_class(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if not args:
      ui.fatal('need class')

    base = args.popleft()
    if args:
      pat = args.popleft()
    else:
      pat = '.'

    from trueseeing.core.context import Context
    with Context(apk, []) as context:
      await context.analyze()
      store = context.store()
      for op in store.query().classes_extends_has_method_named(base, pat):
        cn = store.query().class_name_of(op)
        ui.info(f'{cn}: {op}')

  async def _search_implementing_class(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if not args:
      ui.fatal('need pattern')

    interface = args.popleft()
    if args:
      pat = args.popleft()
    else:
      pat = '.'

    from trueseeing.core.context import Context
    with Context(apk, []) as context:
      await context.analyze()
      store = context.store()
      for op in store.query().classes_implements_has_method_named(interface, pat):
        cn = store.query().class_name_of(op)
        ui.info(f'{cn}: {op}')

  async def _search_defined_method(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    if not args:
      ui.fatal('need classname')

    pat = args.popleft()

    from trueseeing.core.context import Context
    with Context(apk, []) as context:
      await context.analyze()
      store = context.store()
      for op in store.query().classes_has_method_named(pat):
        qn = store.query().qualname_of(op)
        ui.info(f'{qn}: {op}')

  async def _export_context(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()

    if not args:
      ui.fatal('need path')

    root = args.popleft()
    ui.info('exporting target to {root}'.format(root=root))

    import os
    import time
    from trueseeing.core.context import Context

    at = time.time()
    extracted = 0
    with Context(self._target, []) as context:
      with context.store().db as c:
        for path,blob in c.execute('select path,blob from files'):
          target = os.path.join(root, *path.split('/'))
          if extracted % 10000 == 0:
            ui.info(' .. {nr} files'.format(nr=extracted))
          os.makedirs(os.path.dirname(target), exist_ok=True)
          with open(target, 'wb') as f:
            f.write(blob)
            extracted += 1
    ui.success('done: {nr} files ({t:.02f} sec.)'.format(nr=extracted, t=(time.time() - at)))

  async def _use_framework(self, args: deque[str]) -> None:
    _ = args.popleft()

    if not args:
      ui.fatal('need framework apk')

    import os
    from trueseeing.core.tools import invoke_passthru
    from pkg_resources import resource_filename

    apk = args.popleft()

    await invoke_passthru(
      'java -jar {apktool} if {apk}'.format(
        apk=apk,
        apktool=resource_filename(__name__, os.path.join('..', 'libs', 'apktool.jar')),
      ))

  async def _assemble_apk_from_path(self, wd: str, path: str) -> Tuple[str, str]:
    import os
    from pkg_resources import resource_filename
    from trueseeing.core.sign import SigningKey
    from trueseeing.core.tools import invoke_passthru
    await invoke_passthru(
      '(java -jar {apkeditor} b -i {path} -o {wd}/output.apk && java -jar {apksigner} sign --ks {keystore} --ks-pass pass:android {wd}/output.apk)'.format(
        wd=wd, path=path,
        apkeditor=resource_filename(__name__, os.path.join('..', 'libs', 'apkeditor.jar')),
        apksigner=resource_filename(__name__, os.path.join('..', 'libs', 'apksigner.jar')),
        keystore=await SigningKey().key(),
      )
    )
    return os.path.join(wd, 'output.apk'), os.path.join(wd, 'output.apk.idsig')

  def _move_apk(self, src: str, dest: str) -> None:
    import shutil
    shutil.move(src, dest)
    try:
      shutil.move(src.replace('.apk', '.apk.idsig'), dest.replace('.apk', '.apk.idsig'))
    except OSError:
      pass

  async def _assemble(self, args: deque[str]) -> None:
    self._require_target('need target (i.e. output apk filename)')
    assert self._target is not None

    cmd = args.popleft()

    if not args:
      ui.fatal('need root path')

    import os
    import time
    import shutil
    from tempfile import TemporaryDirectory

    root = args.popleft()
    apk = self._target
    origapk = apk.replace('.apk', '.apk.orig')

    if os.path.exists(origapk) and not cmd.endswith('!'):
      ui.fatal('backup file exists; force (!) to overwrite')

    opts = self._get_effective_options(self._get_modifiers(args))

    ui.info('assembling {root} -> {apk}'.format(root=root, apk=apk))

    at = time.time()

    with TemporaryDirectory() as td:
      if opts.get('nocache', 0 if os.environ.get('TS2_IN_DOCKER', 0) else 1):
        path = root
      else:
        ui.info('caching content')
        path = os.path.join(td, 'f')
        shutil.copytree(os.path.join(root, '.'), path)

      outapk, outsig = await self._assemble_apk_from_path(td, path)

      if os.path.exists(apk):
        self._move_apk(apk, origapk)

      self._move_apk(outapk, apk)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _disassemble(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    cmd = args.popleft()

    if not args:
      ui.fatal('need output path')

    import os
    import time
    import shutil
    from tempfile import TemporaryDirectory
    from trueseeing.core.tools import invoke_passthru
    from pkg_resources import resource_filename

    path = args.popleft()
    apk = self._target

    if os.path.exists(path) and not cmd.endswith('!'):
      ui.fatal('output path exists; force (!) to overwrite')

    ui.info('disassembling {apk} -> {path}'.format(apk=apk, path=path))

    at = time.time()

    with TemporaryDirectory() as td:
      await invoke_passthru(
        '(java -jar {apkeditor} d -o {td}/f -i {apk} {s})'.format(
          td=td, apk=apk,
          s='-dex' if 's' in cmd else '',
          apkeditor=resource_filename(__name__, os.path.join('..', 'libs', 'apkeditor.jar'))
        )
      )

      if os.path.exists(path):
        shutil.rmtree(path)
      shutil.move(os.path.join(td, 'f'), path)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _exploit_discard(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    import os.path
    import shutil
    import time
    from trueseeing.core.context import Context

    at = time.time()

    with Context(self._target, []) as context:
      path = os.path.join(context.wd, 'p')
      if not os.path.exists(path):
        ui.fatal('nothing to discard')

      ui.info('discarding patches to {apk}'.format(apk=apk))
      shutil.rmtree(path)
      ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _exploit_apply(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    cmd = args.popleft()

    import os
    import time
    from tempfile import TemporaryDirectory
    from trueseeing.core.context import Context

    apk = self._target
    origapk = apk.replace('.apk', '.apk.orig')

    if os.path.exists(origapk) and not cmd.endswith('!'):
      ui.fatal('backup file exists; force (!) to overwrite')

    at = time.time()

    with Context(self._target, []) as context:
      path = os.path.join(context.wd, 'p')
      if not os.path.exists(path):
        ui.fatal('nothing to apply')

      with TemporaryDirectory() as td:
        ui.info('applying patches to {apk}'.format(apk=apk))
        outapk, outsig = await self._assemble_apk_from_path(td, path)

        if os.path.exists(apk):
          self._move_apk(apk, origapk)

        self._move_apk(outapk, apk)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _prep_exploit(self, ctx: Context) -> None:
    import os.path
    from pkg_resources import resource_filename
    from trueseeing.core.tools import invoke_passthru

    ctx.create(exist_ok=True)

    apk = os.path.join(ctx.wd, 'target.apk')
    path = os.path.join(ctx.wd, 'p')
    if not os.path.exists(path):
      await invoke_passthru(
        '(java -jar {apkeditor} d -o {path} -i {apk} -dex)'.format(
          apk=apk, path=path,
          apkeditor=resource_filename(__name__, os.path.join('..', 'libs', 'apkeditor.jar'))
        )
      )

  async def _exploit_disable_pinning(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()

    import os.path
    import time
    import shutil
    import random
    from pkg_resources import resource_filename
    from trueseeing.core.context import Context

    ui.info('disabling declarative TLS pinning {apk}'.format(apk=self._target))

    at = time.time()

    with Context(self._target, []) as context:
      await self._prep_exploit(context)
      path = os.path.join(context.wd, 'p', 'AndroidManifest.xml')
      key = 'nsc{:04x}'.format(random.randint(0, 2**16))

      manif = self._parsed_manifest(path)
      for e in manif.xpath('.//application'):
        e.attrib['{http://schemas.android.com/apk/res/android}usesCleartextTraffic'] = "true"
        e.attrib['{http://schemas.android.com/apk/res/android}networkSecurityConfig'] = f'@xml/{key}'
      with open(path, 'wb') as f:
        f.write(self._manifest_as_xml(manif))

      # XXX
      path = os.path.join(context.wd, 'p', 'resources', 'package_1', 'res', 'xml', f'{key}.xml')
      nscpath = resource_filename(__name__, os.path.join('..', 'libs', 'nsc.xml'))
      shutil.copy(nscpath, path)

      # XXX
      import lxml.etree as ET
      path = os.path.join(context.wd, 'p', 'resources', 'package_1', 'res', 'values', 'public.xml')
      with open(path, 'rb') as f:
        root = ET.fromstring(f.read(), parser=ET.XMLParser(recover=True))
      if root.xpath('./public[@type="xml"]'):
        maxid = max(int(e.attrib["id"], 16) for e in root.xpath('./public[@type="xml"]'))
        n = ET.SubElement(root, 'public')
        n.attrib['id'] = f'0x{maxid+1:08x}'
        n.attrib['type'] = 'xml'
        n.attrib['name'] = key
      else:
        maxid = (max(int(e.attrib["id"], 16) for e in root.xpath('./public')) & 0xffff0000)
        n = ET.SubElement(root, 'public')
        n.attrib['id'] = f'0x{maxid+0x10000:08x}'
        n.attrib['type'] = 'xml'
        n.attrib['name'] = key

      with open(path, 'wb') as f1:
        f1.write(ET.tostring(root))

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _exploit_enable_debug(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()

    import os.path
    import time
    from trueseeing.core.context import Context

    ui.info('enabling debug {apk}'.format(apk=self._target))

    at = time.time()

    with Context(self._target, []) as context:
      await self._prep_exploit(context)
      path = os.path.join(context.wd, 'p', 'AndroidManifest.xml')
      manif = self._parsed_manifest(path)
      for e in manif.xpath('.//application'):
        e.attrib['{http://schemas.android.com/apk/res/android}debuggable'] = "true"
      with open(path, 'wb') as f:
        f.write(self._manifest_as_xml(manif))

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _exploit_enable_backup(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()

    import os.path
    import time
    from trueseeing.core.context import Context

    ui.info('enabling full backup {apk}'.format(apk=self._target))

    at = time.time()

    with Context(self._target, []) as context:
      await self._prep_exploit(context)
      path = os.path.join(context.wd, 'p', 'AndroidManifest.xml')
      manif = self._parsed_manifest(path)
      for e in manif.xpath('.//application'):
        e.attrib['{http://schemas.android.com/apk/res/android}allowBackup'] = "true"
        if '{http://schemas.android.com/apk/res/android}fullBackupContent' in e.attrib:
          del e.attrib['{http://schemas.android.com/apk/res/android}fullBackupContent']
      with open(path, 'wb') as f:
        f.write(self._manifest_as_xml(manif))

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _exploit_patch_target_api_level(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    cmd = args.popleft()

    try:
      level = int(args.popleft())
    except (IndexError, ValueError):
      ui.fatal('need API level')

    import os.path
    import time
    from trueseeing.core.context import Context

    ui.info('retargetting API level {level} {apk}'.format(level=level, apk=self._target))

    at = time.time()

    with Context(self._target, []) as context:
      await self._prep_exploit(context)
      path = os.path.join(context.wd, 'p', 'AndroidManifest.xml')
      manif = self._parsed_manifest(path)
      for e in manif.xpath('.//uses-sdk'):
        e.attrib['{http://schemas.android.com/apk/res/android}targetSdkVersion'] = str(level)
        minLevel = int(e.attrib.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '1'))
        if level < minLevel:
          if not cmd.endswith('!'):
            ui.fatal('cannot target API level below requirement ({minlv}); force (!) to downgrade altogether'.format(minlv=minLevel))
          else:
            ui.warn('downgrading the requirement')
            e.attrib['{http://schemas.android.com/apk/res/android}minSdkVersion'] = str(level)
      with open(path, 'wb') as f:
        f.write(self._manifest_as_xml(manif))

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _exploit_device_list_packages(self, args: deque[str]) -> None:
    _ = args.popleft()

    ui.info('listing packages')

    import time
    import re
    from trueseeing.core.device import AndroidDevice

    at = time.time()
    nr = 0
    for m in re.finditer(r'^package:(.*)', await AndroidDevice().invoke_adb('shell pm list package'), re.MULTILINE):
      p = m.group(1)
      ui.info(p)
      nr += 1
    ui.success('done, {nr} packages found ({t:.02f} sec.)'.format(nr=nr, t=(time.time() - at)))

  async def _exploit_device_copyout(self, args: deque[str]) -> None:
    cmd = args.popleft()
    if not args:
      ui.fatal('need package name')

    target = args.popleft()

    import os
    if not args:
      outfn = f'{target}.tar'
    else:
      outfn = args.popleft()

    if os.path.exists(outfn) and not cmd.endswith('!'):
      ui.fatal('outfile exists; force (!) to overwrite')

    ui.info(f'copying out: {target} -> {outfn}')

    import time
    from trueseeing.core.device import AndroidDevice

    at = time.time()
    tfn = self._generate_tempfilename_for_device()
    await AndroidDevice().invoke_adb_passthru(f'shell "run-as {target} tar -cv . > {tfn}"')
    await AndroidDevice().invoke_adb_passthru(f'pull {tfn} {outfn}')
    await AndroidDevice().invoke_adb_passthru(f'shell rm {tfn}')
    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _exploit_device_copyin(self, args: deque[str]) -> None:
    _ = args.popleft()
    if not args:
      ui.fatal('need package name')

    target = args.popleft()

    import os
    if not args:
      fn = f'{target}.tar'
    else:
      fn = args.popleft()

    if not os.path.exists(fn):
      ui.fatal('bundle file not found')

    ui.info(f'copying in: {fn} -> {target}')

    import time
    from trueseeing.core.device import AndroidDevice

    at = time.time()
    tfn = self._generate_tempfilename_for_device()
    await AndroidDevice().invoke_adb_passthru(f'push {fn} {tfn}')
    await AndroidDevice().invoke_adb_passthru(f'shell "run-as {target} tar -xv < {tfn}; rm -f {tfn}"')
    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  def _generate_tempfilename_for_device(self, dir: Optional[str] = None) -> str:
    import random
    return (f'{dir}/' if dir is not None else '/data/local/tmp/') + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))

  async def _info(self, args: deque[str]) -> None:
    self._require_target()
    assert self._target is not None

    _ = args.popleft()
    apk = self._target

    import os
    from trueseeing.core.context import Context

    boolmap = {True:'yes',False:'no','true':'yes','false':'no',1:'yes',0:'no'}

    ui.info(f'info on {apk}')

    with Context(self._target, []) as context:
      analyzed = os.path.exists(os.path.join(context.wd, '.done'))

      ui.info('path         {}'.format(apk))
      ui.info('size         {}'.format(os.stat(apk).st_size))
      ui.info('fp           {}'.format(context.fingerprint_of()))
      ui.info('ctx          {}'.format(context.wd))
      ui.info('has patch?   {}'.format(boolmap[os.path.exists(os.path.join(context.wd, 'p', 'AndroidManifest.xml'))]))
      ui.info('analyzed?    {}'.format(boolmap[analyzed]))
      if analyzed:
        store = context.store()
        manif = context.parsed_manifest()
        ui.info('pkg          {}'.format(manif.attrib['package']))
        ui.info('perms        {}'.format(len(list(context.permissions_declared()))))
        ui.info('activs       {}'.format(len(list(manif.xpath('.//activity')))))
        ui.info('servs        {}'.format(len(list(manif.xpath('.//service')))))
        ui.info('recvs        {}'.format(len(list(manif.xpath('.//receiver')))))
        ui.info('provs        {}'.format(len(list(manif.xpath('.//provider')))))
        ui.info('int-flts     {}'.format(len(list(manif.xpath('.//intent-filter')))))
        with store.db as c:
          for nr, in c.execute('select count(1) from classes_extends_name where extends_name regexp :pat', dict(pat='^Landroid.*Fragment(Compat)?;$')):
            ui.info('frags        {}'.format(len(list(manif.xpath('.//activity')))))
        for e in manif.xpath('.//application'):
          ui.info('debuggable?  {}'.format(boolmap[e.attrib.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')]))
          ui.info('backupable?  {}'.format(boolmap[e.attrib.get('{http://schemas.android.com/apk/res/android}allowBackup', 'false')]))
          ui.info('netsecconf?  {}'.format(boolmap[e.attrib.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig') is not None]))
        if manif.xpath('.//uses-sdk'):
          for e in manif.xpath('.//uses-sdk'):
            ui.info('api min      {}'.format(int(e.attrib.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '1'))))
            ui.info('api tgt      {}'.format(int(e.attrib.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '1'))))
        else:
          dom = context._parsed_apktool_yml()
          ui.info('api min      {} (apktool)'.format(int(dom['sdkInfo'].get('minSdkVersion', '1'))))
          ui.info('api tgt      {} (apktool)'.format(int(dom['sdkInfo'].get('targetSdkVersion', '1'))))
        with store.db as c:
          for nr, in c.execute('select count(1) from analysis_issues'):
            ui.info('issues       {}{}'.format(nr, ('' if nr else ' (not scanned yet?)')))
          for nr, in c.execute('select count(1) from ops where idx=0'):
            ui.info('ops          {}'.format(nr))
          for nr, in c.execute('select count(1) from class_class_name'):
            ui.info('classes      {}'.format(nr))
          for nr, in c.execute('select count(1) from method_method_name'):
            ui.info('methods      {}'.format(nr))

  async def _set_target(self, args: deque[str]) -> None:
    _ = args.popleft()

    if not args:
      ui.fatal('need path')

    self._target = args.popleft()

  def _parsed_manifest(self, path: str) -> Any:
    import lxml.etree as ET
    with open(path, 'rb') as f:
      return ET.parse(f, parser=ET.XMLParser(recover=True))

  def _manifest_as_xml(self, manifest: Any) -> bytes:
    import lxml.etree as ET
    assert manifest is not None
    return ET.tostring(manifest) # type: ignore[no-any-return]
