from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from typing import Type, Iterator
  from trueseeing.api import Detector

def discover() -> Iterator[Type[Detector]]:
  from trueseeing.api import Detector
  from trueseeing.core.model.sig import DetectorMixin
  from importlib import import_module
  from trueseeing.core.tools import get_public_subclasses, get_missing_methods

  for mod in _discover_modules():
    m = import_module(mod)
    for c in get_public_subclasses(m, Detector, [DetectorMixin]):  # type:ignore[type-abstract]
      assert not get_missing_methods(c)
      yield c

def _discover_modules() -> Iterator[str]:
  from importlib.resources import files
  from glob import iglob
  import os.path
  basepath = str(files('trueseeing.sig'))
  for path in iglob(os.path.join(basepath, '**', '*.py'), recursive=True):
    yield 'trueseeing.sig.{}'.format(os.path.relpath(path, basepath).replace('.py', '').replace('/', '.'))
