from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from typing import Type, Iterator
  from trueseeing.api import Command

def discover() -> Iterator[Type[Command]]:
  from trueseeing.api import Command
  from importlib import import_module
  from trueseeing.core.model.cmd import CommandMixin
  from trueseeing.core.tools import get_public_subclasses, has_mandatory_ctor

  for mod in _discover_modules():
    m = import_module(mod)
    for c in get_public_subclasses(m, Command, [CommandMixin]):  # type:ignore[type-abstract]
      assert has_mandatory_ctor(c), f'missing the static ctor: {c!r}'
      yield c

def _discover_modules() -> Iterator[str]:
  from importlib.resources import files
  from glob import iglob
  import os.path
  basepath = str(files('trueseeing.app.cmd'))
  for path in iglob(os.path.join(basepath, '**', '*.py'), recursive=True):
    yield 'trueseeing.app.cmd.{}'.format(os.path.relpath(path, basepath).replace('.py', '').replace('/', '.'))
