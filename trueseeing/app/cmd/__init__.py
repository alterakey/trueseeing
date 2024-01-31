from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from typing import Type, Iterator
  from trueseeing.core.model.cmd import Command

def discover() -> Iterator[Type[Command]]:
  from trueseeing.core.model.cmd import Command
  from importlib import import_module
  from trueseeing.core.tools import get_public_subclasses

  for mod in _discover_modules():
    m = import_module(mod)
    for c in get_public_subclasses(m, Command):
      yield c

def _discover_modules() -> Iterator[str]:
  from importlib.resources import files
  from glob import iglob
  import os.path
  basepath = str(files('trueseeing.app.cmd'))
  for path in iglob(os.path.join(basepath, '**', '*.py'), recursive=True):
    yield 'trueseeing.app.cmd.{}'.format(os.path.relpath(path, basepath).replace('.py', '').replace('/', '.'))
