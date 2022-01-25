from __future__ import annotations
import os.path
from typing import TYPE_CHECKING

from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Any, Dict, ClassVar, Optional, Iterable
  from typing_extensions import Final
  from trueseeing.core.context import Context
  from trueseeing.app.shell import Signatures

class Extension:
  _ns: Any
  _inst: ClassVar[Optional[Extension]] = None
  _module_name: Final[str] = 'ext'

  @classmethod
  def get(cls) -> Extension:
    if cls._inst is None:
      cls._inst = Extension()
    return cls._inst

  def __init__(self) -> None:
    self._ns = self._compile()

  def _compile(self) -> Any:
    globals_: Dict[str, Any] = dict(__name__='__main__', ui=ui)
    locals_: Dict[str, Any] = dict()
    try:
      starter = self._importer(os.path.join('~', '.trueseeing2', self._module_name))
      if starter is not None:
        code = compile(starter, filename='<string>', mode='exec')
        exec(code, globals_, locals_)
        return locals_
      else:
        return {}
    except Exception as e:
      ui.warn('Uncaught exception during invocation', exc=e)
      return {}

  def patch_context(self, context: Context) -> None:
    if 'patch_context' in self._ns:
      self._ns['patch_context'](context)

  def patch_signatures(self, sigs: Signatures) -> None:
    if 'patch_signatures' in self._ns:
      self._ns['patch_signatures'](sigs)

  # XXX: gross hack
  def _importer(self, path: str) -> Optional[str]:
    import re
    path = os.path.expandvars(os.path.expanduser(path))
    dirname = os.path.dirname(path)
    basename = os.path.splitext(os.path.basename(path))[0]
    if any([os.path.exists(x) for x in self._as_module_filenames(path)]):
      if re.fullmatch(r'[0-9A-Za-z_]+', basename):
        return f'import sys\ntry:\n sys.dont_write_bytecode=True;sys.path.insert(0,"{dirname}");from {basename} import *\nfinally:\n sys.dont_write_bytecode=False;sys.path.pop(0)'
      else:
        raise ValueError(f'invalid filename: {basename}')
    else:
      return None

  @staticmethod
  def _as_module_filenames(fn: str) -> Iterable[str]:
    for suffix in '', '.pyc', '.py':
      yield fn + suffix
