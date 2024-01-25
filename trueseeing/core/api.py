from __future__ import annotations
from typing import TYPE_CHECKING

import os
import os.path

from trueseeing.signature.base import Detector
from trueseeing.core.ui import ui
from trueseeing.core.env import get_extension_dir, get_extension_dir_v0, get_extension_package_prefix

if TYPE_CHECKING:
  from typing import Any, Dict, ClassVar, Optional, Iterable, Iterator, Type
  from typing_extensions import Final
  from trueseeing.app.inspect import CommandEntry, CommandPatternEntry, OptionEntry, ModifierEntry

class Extension:
  _ns: Any
  _inst: ClassVar[Optional[Extension]] = None
  _module_name: Final[str] = 'ext'
  disabled: ClassVar[bool] = False

  @classmethod
  def get(cls) -> Extension:
    if cls._inst is None:
      cls._inst = Extension()
    return cls._inst

  def __init__(self) -> None:
    self._ns = {}
    if not self.disabled:
      self._ns.update(self._import())
      self._ns.update(self._compile())

  def _import(self) -> Any:
    from importlib import import_module
    from importlib_metadata import packages_distributions
    o = {}
    for n in packages_distributions():
      if not n.startswith(get_extension_package_prefix()):
        continue
      o[n] = import_module(n)
    return o

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

  def get_signatures(self) -> Iterator[Type[Detector]]:
    from inspect import getmembers, isclass
    for _,m in self._ns.items():
      for n, clazz in getmembers(m, lambda x: isclass(x) and x != Detector and issubclass(x, Detector)):
        if not n.startswith('_'):
          yield clazz

  def get_commands(self) -> Iterator[Type[Command]]:
    from inspect import getmembers, isclass
    for _,m in self._ns.items():
      for n, clazz in getmembers(m, lambda x: isclass(x) and x != Command and issubclass(x, Command)):
        if not n.startswith('_'):
          yield clazz

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

class Command:
  def get_commands(self) -> Dict[str, CommandEntry]:
    return dict()
  def get_command_patterns(self) -> Dict[str, CommandPatternEntry]:
    return dict()
  def get_modifiers(self) -> Dict[str, ModifierEntry]:
    return dict()
  def get_options(self) -> Dict[str, OptionEntry]:
    return dict()
