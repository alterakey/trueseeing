from __future__ import annotations
import os
import os.path
from typing import TYPE_CHECKING

from trueseeing.core.ui import ui
from trueseeing.core.env import get_extension_dir, get_extension_dir_v0

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
      starter: Optional[str] = None
      path = get_extension_dir()
      if os.path.isdir(path):
        starter = self._importer(path)
      else:
        for trypath in self._get_extensions_v0():
          if os.path.exists(trypath):
            ui.warn('extension uses old path ({vers}), consider moving it to {path}'.format(vers='v0', path=os.path.join(get_extension_dir(), os.path.basename(trypath))))
            starter = self._importer_v0(trypath)
            break
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
    for n,m in self._ns.items():
      if hasattr(m, 'patch_context'):
        getattr(m, 'patch_context')(context)

  def patch_signatures(self, sigs: Signatures) -> None:
    for n,m in self._ns.items():
      if hasattr(m, 'patch_signatures'):
        getattr(m, 'patch_signatures')(sigs)

  # XXX: gross hack
  def _importer(self, path: str, /, only: Optional[str] = None) -> Optional[str]:
    from glob import iglob
    import re
    path = os.path.expandvars(os.path.expanduser(path))
    mods: Dict[str, str] = dict()
    fns: Iterable[str] = iglob(f'{path}/*') if not only else [os.path.join(path, only)]
    for fn in fns:
      bn = os.path.basename(fn)
      ns, ne = os.path.splitext(bn)
      if not re.fullmatch(r'[0-9A-Za-z_]+', ns):
        ui.warn(f'cannot load extension {bn}: invalid filename')
        continue
      if ne and ne not in ['py', 'pyc', 'pyo']:
        ui.warn(f'cannot load extension {bn}: invalid filename')
        continue
      mods[bn] = ns

    return 'import sys\ntry:\n sys.dont_write_bytecode=True;sys.path.insert(0,"{path}");\n{importblock}\nfinally:\n sys.dont_write_bytecode=False;sys.path.pop(0);del sys'.format(
      path=path,
      importblock='\n'.join([
        ' try:\n'
        '  import {ns}\n'
        ' except Exception as e:\n'
        '  ui.warn(f"cannot load extension {bn}: {{e}}")\n'.format(ns=ns, bn=bn) for bn, ns in mods.items()
      ])
    )

  def _importer_v0(self, path: str) -> Optional[str]:
    root = get_extension_dir_v0()
    return self._importer(root, only=os.path.relpath(path, start=root))

  def _get_extensions_v0(self) -> Iterable[str]:
    for fn in 'ext.pyc', 'ext.py', 'ext':
      yield os.path.join(get_extension_dir_v0(), fn)
