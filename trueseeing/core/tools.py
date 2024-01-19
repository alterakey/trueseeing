from __future__ import annotations
from typing import TYPE_CHECKING

import asyncio
import functools
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Any, Optional, AsyncIterable, TypeVar, List
  T = TypeVar('T')

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
  if p.returncode:
    from subprocess import CalledProcessError
    raise CalledProcessError(p.returncode, args, out, err)

@functools.lru_cache(maxsize=1)
def _detect_build_tools() -> str:
  import os.path
  import glob
  try:
    return list(sorted(glob.glob(os.path.join(os.environ['ANDROID_HOME'], 'build-tools', '*'))))[-1]
  except KeyError:
    ui.fatal('ANDROID_HOME required')
  except IndexError:
    ui.fatal('No build tool detected; install one')

def _invoke_path() -> Any:
  import os
  env = os.environ
  if not env.get('TS2_IN_DOCKER'):
    env.update(dict(PATH=os.pathsep.join([_detect_build_tools(), env.get('PATH', '')])))
  return env

async def invoke(as_: str, redir_stderr: bool = False) -> str:
  from subprocess import PIPE, STDOUT
  p = await asyncio.create_subprocess_shell(as_, stdout=PIPE, stderr=(STDOUT if redir_stderr else None), env=_invoke_path())
  out, _ = await p.communicate()
  _check_return_code(p, as_, out, None)
  return out.decode('UTF-8')

async def invoke_passthru(as_: str, nocheck: bool = False) -> None:
  p = await asyncio.create_subprocess_shell(as_, env=_invoke_path())
  await p.communicate()
  if not nocheck:
    _check_return_code(p, as_, None, None)

async def try_invoke(as_: str) -> Optional[str]:
  from subprocess import CalledProcessError
  try:
    return await invoke(as_)
  except CalledProcessError:
    return None
