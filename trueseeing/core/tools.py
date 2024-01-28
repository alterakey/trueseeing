from __future__ import annotations
from typing import TYPE_CHECKING

import asyncio
from functools import cache
from contextlib import contextmanager
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from pathlib import Path
  from typing import Any, Optional, AsyncIterable, TypeVar, List, Iterator, TypedDict, AsyncIterator
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

async def list_async(iter: AsyncIterable[T]) -> List[T]:
  o = []
  async for t in iter:
    o.append(t)
  return o

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
  from subprocess import PIPE, STDOUT
  p = await asyncio.create_subprocess_shell(as_, stdout=PIPE, stderr=(STDOUT if redir_stderr else None))
  out, _ = await p.communicate()
  _check_return_code(p, as_, out, None)
  return out.decode('UTF-8')

async def invoke_passthru(as_: str, nocheck: bool = False) -> None:
  p = await asyncio.create_subprocess_shell(as_)
  await p.communicate()
  if not nocheck:
    _check_return_code(p, as_, None, None)

async def invoke_streaming(as_: str, redir_stderr: bool = False) -> AsyncIterator[bytes]:
  from subprocess import PIPE, STDOUT
  p = await asyncio.create_subprocess_shell(as_, stdout=PIPE, stderr=(STDOUT if redir_stderr else None))
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

@contextmanager
def toolchains() -> Iterator[Toolchain]:
  from importlib.resources import files, as_file
  require_in_path('java', 'java -version')
  libs = files('trueseeing')/'libs'
  with as_file(libs/'apkeditor.jar') as apkeditorpath:
    with as_file(libs/'apksigner.jar') as apksignerpath:
      with as_file(libs/'abe.jar') as abepath:
        yield dict(
          apkeditor=apkeditorpath,
          apksigner=apksignerpath,
          abe=abepath,
        )

def move_apk(src: str, dest: str) -> None:
  import shutil
  shutil.move(src, dest)
  try:
    shutil.move(src.replace('.apk', '.apk.idsig'), dest.replace('.apk', '.apk.idsig'))
  except OSError:
    pass

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
