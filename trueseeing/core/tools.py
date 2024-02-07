from __future__ import annotations
from typing import TYPE_CHECKING

from functools import cache
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from pathlib import Path
  from typing import Any, Optional, TypeVar, Iterator, TypedDict, AsyncIterator, Type, Iterable, FrozenSet, Dict, Set
  T = TypeVar('T')

  class Toolchain(TypedDict):
    apkeditor: Path
    apksigner: Path
    abe: Path

def noneif(x: Any, defaulter: Any) -> Any:
  if x is not None:
    return x
  else:
    if callable(defaulter):
      return defaulter()
    else:
      return defaulter

def _check_return_code(p: Any, args: Any, out: Any, err: Any) -> None:
  code: int
  if isinstance(p, int):
    code = p
  elif hasattr(p, 'returncode'):
    code = p.returncode
  if code:
    from subprocess import CalledProcessError
    raise CalledProcessError(code, args, out, err)

@cache
def require_in_path(cmd: str, cmdline: str) -> None:
  from subprocess import run, CalledProcessError
  try:
    run(cmdline, capture_output=True, check=True, shell=True)
  except CalledProcessError:
    ui.fatal('not found: {cmd}')

async def invoke(as_: str, redir_stderr: bool = False) -> str:
  from asyncio import create_subprocess_shell
  from subprocess import PIPE, STDOUT
  p = await create_subprocess_shell(as_, stdout=PIPE, stderr=(STDOUT if redir_stderr else None))
  out, _ = await p.communicate()
  _check_return_code(p, as_, out, None)
  return out.decode('UTF-8')

async def invoke_passthru(as_: str, nocheck: bool = False) -> None:
  from asyncio import create_subprocess_shell
  p = await create_subprocess_shell(as_)
  await p.communicate()
  if not nocheck:
    _check_return_code(p, as_, None, None)

async def invoke_streaming(as_: str, redir_stderr: bool = False) -> AsyncIterator[bytes]:
  from asyncio import create_subprocess_shell
  from subprocess import PIPE, STDOUT
  p = await create_subprocess_shell(as_, stdout=PIPE, stderr=(STDOUT if redir_stderr else None))
  if p.stdout is not None:
    async for l in p.stdout:
      yield l
  _check_return_code(await p.wait(), as_, None, None)

async def try_invoke(as_: str) -> Optional[str]:
  from subprocess import CalledProcessError
  try:
    return await invoke(as_)
  except CalledProcessError:
    return None

def copytree(src: str, dst: str, divisor: Optional[int] = 256) -> Iterator[int]:
  import os
  from shutil import copy2, copystat

  nr = 0
  for sp, dns, fns in os.walk(src):
    dp = os.path.realpath(os.path.join(dst, os.path.relpath(sp, src)))
    for dn in dns:
      os.makedirs(os.path.join(dp, dn), exist_ok=True)
      copystat(os.path.join(sp, dn), os.path.join(dp, dn))
    for fn in fns:
      copy2(os.path.join(sp, fn), os.path.join(dp, fn))
      if divisor is None or (nr % divisor == 0):
        yield nr
      nr += 1

def copy_from_pack(src: str, dst: str, prefix: str, divisor: Optional[int] = 256) -> Iterator[int]:
  import tarfile

  nr = 0
  with tarfile.open(src) as tf:
    for name in tf.getnames():
      if name.startswith(prefix):
        tf.extract(name, dst)
      if divisor is None or (nr % divisor == 0):
        yield nr
      nr += 1

def move_as_output(src: str, dst: str, divisor: Optional[int] = 256, allow_orphans: bool = False) -> Iterator[int]:
  import os
  from trueseeing.core.env import is_in_container
  if not is_in_container():
    try:
      os.rename(src, dst)
      yield 0
      return
    except OSError:
      pass

  nr = 0

  from shutil import copy2, copystat
  for sp, dns, fns in os.walk(src, topdown=False):
    dp = os.path.realpath(os.path.join(dst, os.path.relpath(sp, src)))
    for dn in dns:
      copystat(os.path.join(sp, dn), os.path.join(dp, dn))
      if not allow_orphans:
        os.rmdir(os.path.join(sp, dn))
    for fn in fns:
      os.makedirs(dp, exist_ok=True)
      copy2(os.path.join(sp, fn), os.path.join(dp, fn))
      if not allow_orphans:
        os.remove(os.path.join(sp, fn))
      if divisor is None or (nr % divisor == 0):
        yield nr
      nr += 1

def pack_as_output(src: str, dst: str, prefix: str, subformat: str, divisor: Optional[int] = 256, allow_orphans: bool = False) -> Iterator[int]:
  import os

  nr = 0

  import tarfile
  kwargs: Dict[str, int] = dict()
  if subformat in ['gz']:
    kwargs.update(dict(compresslevel=3))

  with tarfile.open(dst, 'w:{}'.format(subformat), **kwargs) as tf:  # type: ignore[arg-type]
    for sp, dns, fns in os.walk(src, topdown=False):
      dp = os.path.join(prefix, os.path.relpath(sp, src))
      for dn in dns:
        tf.add(os.path.join(sp, dn), arcname=os.path.join(dp, dn), recursive=False)
        if not allow_orphans:
          os.rmdir(os.path.join(sp, dn))
      for fn in fns:
        tf.add(os.path.join(sp, fn), arcname=os.path.join(dp, fn), recursive=False)
        if not allow_orphans:
          os.remove(os.path.join(sp, fn))
        if divisor is None or (nr % divisor == 0):
          yield nr
        nr += 1

def get_public_subclasses(mod: Any, typ: Type[T], typs: Iterable[Type[T]] = []) -> Iterator[Type[T]]:
  from inspect import getmembers, isclass
  for n, clazz in getmembers(mod, lambda x: isclass(x) and x != typ and (x not in typs) and issubclass(x, typ)):
    if not n.startswith('_'):
      yield clazz

def get_missing_methods(clazz: Any) -> FrozenSet[str]:
  from inspect import isclass
  assert isclass(clazz)
  return getattr(clazz, '__abstractmethods__', frozenset())

def get_fully_qualified_classname(clazz: Any) -> str:
  return '.'.join([clazz.__module__, clazz.__name__])

def discover_modules_under(anchor: str) -> Iterator[str]:
  import os.path
  import re
  from importlib.resources import files
  from glob import iglob
  seen: Set[str] = set()
  basepath = str(files(anchor))
  for path in iglob(os.path.join(basepath, '**', '*.p*'), recursive=True):
    if '__' in path or os.path.basename(path).startswith('_') or not re.search(r'\.pyc?$', path):
      continue
    n = '{}.{}'.format(anchor, re.sub(r'\.pyc?$', '', os.path.relpath(path, basepath)).replace('/', '.'))
    if n not in seen:
      seen.add(n)
      yield n
