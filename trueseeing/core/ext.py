from __future__ import annotations
from typing import TYPE_CHECKING

import os
import os.path

from functools import cache
from trueseeing.core.ui import ui
from trueseeing.core.env import get_extension_dir, get_extension_dir_v0, get_extension_package_prefix

if TYPE_CHECKING:
  from typing import Any, Dict, ClassVar, Optional, Iterable, Iterator, Type, TypeVar
  from typing_extensions import Final
  from trueseeing.api import Command, Signature, FileFormatHandler

  T = TypeVar('T')

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
    import sys
    from glob import iglob
    from importlib import import_module
    from importlib_metadata import packages_distributions

    o = {}
    prefix = get_extension_package_prefix()
    for n in packages_distributions():
      if not n.startswith(prefix):
        continue
      o[n] = import_module(n)
    # We need to discover *.pth by our own
    for p in sys.path:
      if os.path.isfile(p):
        continue
      for path in iglob('{}/{}*.pth'.format(p, prefix)):
        n = os.path.basename(path).replace('.pth', '')
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

  def get_signatures(self) -> Iterator[Type[Signature]]:
    from trueseeing.api import Signature
    from trueseeing.core.tools import get_public_subclasses, get_missing_methods
    for _, m in self._ns.items():
      for clazz in get_public_subclasses(m, Signature):  # type: ignore[type-abstract]
        missing = get_missing_methods(clazz)
        if missing:
          from trueseeing.core.tools import get_fully_qualified_classname
          ui.warn('ignoring signature {}: missing methods: {}'.format(get_fully_qualified_classname(clazz), ', '.join(missing)))
          continue
        yield clazz

  @cache
  def get_commands(self) -> Iterator[Type[Command]]:
    from trueseeing.api import Command
    from trueseeing.core.tools import get_public_subclasses, get_missing_methods
    for _, m in self._ns.items():
      for clazz in get_public_subclasses(m, Command):  # type: ignore[type-abstract]
        missing = get_missing_methods(clazz)
        if missing:
          from trueseeing.core.tools import get_fully_qualified_classname
          ui.warn('ignoring command {}: missing methods: {}'.format(get_fully_qualified_classname(clazz), ', '.join(missing)))
          continue
        yield clazz

  def get_fileformathandlers(self) -> Iterator[Type[FileFormatHandler]]:
    from trueseeing.api import FileFormatHandler
    from trueseeing.core.tools import get_public_subclasses, get_missing_methods
    for _, m in self._ns.items():
      for clazz in get_public_subclasses(m, FileFormatHandler):  # type: ignore[type-abstract]
        missing = get_missing_methods(clazz)
        if missing:
          from trueseeing.core.tools import get_fully_qualified_classname
          ui.warn('ignoring file format handler  {}: missing methods: {}'.format(get_fully_qualified_classname(clazz), ', '.join(missing)))
          continue
        yield clazz

  # XXX: gross hack
  def _importer(self, path: str, *, only: Optional[str] = None) -> Optional[str]:
    from glob import iglob
    import re
    path = os.path.expandvars(os.path.expanduser(path))
    mods: Dict[str, str] = dict()

    def _get_seeds() -> Iterator[str]:
      if only:
        yield os.path.join(path, only)
      else:
        for n in iglob(f'{path}/*'):
          yield n

    def _discover() -> Iterator[str]:
      for n in _get_seeds():
        bn = os.path.basename(n)
        if os.path.isfile(n):
          ns, ne = os.path.splitext(bn)
          if not (ne in ['py', 'pyc', 'pyo']):
            ui.warn(f'cannot load extension {bn}: invalid filename')
            continue
          if not re.fullmatch(r'[0-9A-Za-z_]+', ns):
            ui.warn(f'cannot load extension {bn}: invalid filename')
            continue
          yield n
        elif os.path.isdir(n):
          if os.path.exists(os.path.join(n, '__init__.py')):
            yield n
            continue
          found = False
          for nn in iglob(f'{n}/*'):
            if os.path.exists(os.path.join(nn, '__init__.py')):
              yield nn
              found = True
          if not found:
            ui.warn(f'cannot load extension {bn}: need to be or contain a module')
        else:
          ui.warn(f'cannot load extension {bn}: invalid filetype')

    for n in _discover():
      ns, _ = os.path.splitext(os.path.basename(n))
      mods[ns] = n

    return 'import sys\ntry:\n sys.dont_write_bytecode=True;\n{importblock}\nfinally:\n sys.dont_write_bytecode=False;del sys'.format(
      importblock='\n'.join([
        ' try:\n'
        '  sys.path[0:0]=["{path}"]\n'
        '  import {ns}\n'
        ' except Exception as e:\n'
        '  ui.warn(f"cannot load extension {bn}: {{e}}")\n'
        ' finally:\n'
        '  del sys.path[0]\n'.format(ns=ns, bn=os.path.basename(path), path=os.path.dirname(path)) for ns, path in mods.items()
      ])
    )

  def _importer_v0(self, path: str) -> Optional[str]:
    root = get_extension_dir_v0()
    return self._importer(root, only=os.path.relpath(path, start=root))

  def _get_extensions_v0(self) -> Iterable[str]:
    for fn in 'ext.pyc', 'ext.py', 'ext':
      yield os.path.join(get_extension_dir_v0(), fn)
