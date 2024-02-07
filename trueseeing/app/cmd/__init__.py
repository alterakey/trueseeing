from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from typing import Type, Iterator
  from trueseeing.api import Command

def discover() -> Iterator[Type[Command]]:
  from trueseeing.api import Command
  from importlib import import_module
  from trueseeing.core.model.cmd import CommandMixin
  from trueseeing.core.tools import get_public_subclasses, get_missing_methods, discover_modules_under

  for mod in discover_modules_under('trueseeing.app.cmd'):
    m = import_module(mod)
    for c in get_public_subclasses(m, Command, [CommandMixin]):  # type:ignore[type-abstract]
      assert not get_missing_methods(c)
      yield c
