from __future__ import annotations
from typing import TYPE_CHECKING

import re
from collections import deque
from shlex import shlex

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Dict, Tuple
  from trueseeing.api import CommandHelper, Command, CommandMap, CommandPatternMap

class AliasCommand(CommandMixin):
  _aliases: Dict[str, str]
  _macros: Dict[str, Tuple[int, str, deque[str]]]

  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper
    self._aliases = dict()
    self._macros = dict()

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return AliasCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      '?$?':dict(e=self._help_alias, n='?$?', d='alias help'),
    }

  def get_command_patterns(self) -> CommandPatternMap:
    return {
      r'\$[a-zA-Z0-9=]+':dict(e=self._alias, n='$alias=value', d='alias command'),
      r'\(.+\)':dict(e=self._alias2, raw=True, n='(macro x y; cmd; cmd; ..)', d='define macro'),
      r'\.\(.+\)':dict(e=self._alias2_call, raw=True, n='.(macro x y)', d='call macro'),
      r'^\(\*$':dict(e=self._help_alias2, raw=True, n='(*', d='macro help'),
    }

  async def _help_alias(self, args: deque[str]) -> None:
    if self._aliases:
      ui.success('Aliases:')
      width = 2 + max([len(k) for k in self._aliases.keys()])
      for k in sorted(self._aliases):
        ui.stderr(
          f'${{n:<{width}s}}{{d}}'.format(n=k, d=self._aliases[k])
        )
    else:
      ui.success('no alias known')

  async def _help_alias2(self, line: str) -> None:
    if self._macros:
      ui.success('Macroes:')
      width = 2 + max([len(k) for k in self._macros.keys()])
      for k in sorted(self._macros):
        ui.stderr(
          f'{{n:<{width}s}}{{d}}'.format(n=k, d=self._macros[k][1])
        )
    else:
      ui.success('no macro known')

  async def _alias(self, args: deque[str]) -> None:
    cmd = args.popleft()
    n = cmd[1:]

    if args:
      op = args.popleft()
      if op != '=':
        ui.fatal('alias cannot take arguments')
      if args:
        val = args.popleft()
      else:
        val = None
    else:
      op = None
      val = None

    if op is None:
      try:
        v = self._aliases[n]
      except KeyError:
        ui.error('invalid command, type ? for help')
      else:
        await self._helper.run(v)
    elif op == '=':
      if val is not None:
        self._aliases[n] = val
      else:
        del self._aliases[n]

  async def _alias2(self, line: str) -> None:
    lex = shlex(line, posix=True, punctuation_chars=';=')
    lex.wordchars += '@:,!$'

    args = deque(lex)
    args.popleft()

    newcmd = args.popleft()
    if not re.fullmatch('-?[a-zA-Z0-9_]+', newcmd):
      ui.fatal(f'invalid macro name: {newcmd}')

    argn = 0
    while args:
      t = args.popleft()
      if re.fullmatch(';+', t) or t == ')':
        break
      elif not re.fullmatch('[a-zA-Z0-9_]+', t):
        ui.fatal(f'invalid arg name: {t}')
      else:
        argn += 1

    body: deque[str] = deque()
    while args:
      t = args.popleft()
      if t == ')':
        break
      else:
        body.append(t)

    if body:
      if newcmd.startswith('-'):
        ui.fatal(f'invalid macro name: {newcmd}')
      for t in body:
        m = re.search(r'\$([0-9]+)', t)
        if m:
          nr = int(m.group(1))
          if not nr < argn:
            ui.fatal('arg index out of range: {} (macro takes {} args)'.format(m.group(0), argn))
    else:
      if not newcmd.startswith('-'):
        ui.fatal('invalid macro: no body found')
      else:
        cmd = newcmd[1:]
        try:
          del self._macros[cmd]
        except KeyError:
          ui.fatal(f'macro not found: {cmd}')
        return

    self._macros[newcmd] = argn, line, body

  async def _alias2_call(self, line: str) -> None:
    content = re.match(r'\.\((.+)\)', line)
    assert content is not None
    lex = shlex(content.group(1), posix=True, punctuation_chars=';=')
    lex.wordchars += '@:,!$'

    tokens = deque(lex)
    cmd = tokens.popleft()

    argn, _, body = self._macros[cmd]
    args = []

    for _ in range(argn):
      try:
        t = tokens.popleft()
      except IndexError:
        ui.fatal('not enough arg (requires {})'.format(argn))
      else:
        args.append(t)

    if tokens:
      ui.warn('igonring extra {} args'.format(len(tokens)))

    asl: deque[str] = deque()
    for t in body:
      asl.append(re.sub(r'\$([0-9]+)', lambda m: args[int(m.group(1))], t))
    await self._helper.run_cmd(asl, None)
