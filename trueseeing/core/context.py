from __future__ import annotations
from typing import TYPE_CHECKING, overload

import os.path
from abc import ABC, abstractmethod
from functools import cache

if TYPE_CHECKING:
  from typing import List, Dict, Optional, Set, Literal, Any, Mapping, AsyncIterator, Tuple, Iterator
  from typing_extensions import Self
  from trueseeing.api import FormatEntry
  from trueseeing.core.store import Store
  from trueseeing.core.android.context import APKContext

  ContextType = str
  ContextInfo = Mapping[str, Any]

class FileOpener:
  _formats: Dict[str, FormatEntry]

  def __init__(self, force_opener: Optional[str] = None) -> None:
    from trueseeing.core.config import Configs
    self._confbag = Configs.get().bag
    self._formats = dict()
    self._force_opener = force_opener
    self._init_formats()

  def get_context(self, path: str) -> Context:
    from trueseeing.core.exc import InvalidFileFormatError
    if not self._force_opener:
      import re

      def _key(x: Tuple[str, FormatEntry]) -> int:
        try:
          return len(x[1]['r'])
        except KeyError:
          from trueseeing.core.ui import ui
          ui.warn('{} ({}): old-style format entry detected; update definition'.format(x[1]['d'], x[0]))
          return len(x[0])

      for k,v in sorted(self._formats.items(), key=_key, reverse=True):
        if not re.search(v.get('r', k), path, re.IGNORECASE):
          continue
        c = v['e'](path)
        if c is None:
          continue
        return c
      raise InvalidFileFormatError()
    else:
      if self._force_opener in self._formats:
        c = self._formats[self._force_opener]['e'](path)
        if c is not None:
          return c
      raise InvalidFileFormatError()

  def get_formats(self) -> Iterator[Mapping[str, str]]:
    for k,v in self._formats.items():
      yield dict(n=k, d=v['d'])

  def _init_formats(self) -> None:
    from trueseeing.core.ext import Extension

    self._formats.update({
      'apk':dict(e=self._handle_apk, r=r'\.apk$', d='Android application package'),
      'xapk':dict(e=self._handle_xapk, r=r'\.xapk$', d='Android appllication bundle'),
      'ipa': dict(e=self._handle_ipa, r=r'\.ipa$', d='iOS application archive'),
    })

    for clazz in Extension.get().get_fileformathandlers():
      t = clazz.create()
      self._formats.update(t.get_formats())
      self._confbag.update(t.get_configs())

  def _handle_apk(self, path: str) -> Optional[Context]:
    from trueseeing.core.android.context import APKContext
    return APKContext(path)

  def _handle_xapk(self, path: str) -> Optional[Context]:
    from trueseeing.core.android.context import XAPKContext
    return XAPKContext(path)

  def _handle_ipa(self, path: str) -> Optional[Context]:
    from trueseeing.core.ios.context import IPAContext
    return IPAContext(path)

class Context(ABC):
  _path: str
  _excludes: List[str]
  _store: Optional[Store] = None
  _wd: Optional[str] = None

  def __init__(self, path: str) -> None:
    self._path = os.path.realpath(path)
    self._excludes = []
    # FIXME: is there a strict need of caching here?
    _ = self.wd

  @property
  def target(self) -> str:
    return self._path

  @property
  def wd(self) -> str:
    if self._wd is None:
      self._wd = self._get_workdir()
    return self._wd

  @property
  def excludes(self) -> List[str]:
    return self._excludes

  @excludes.setter
  def excludes(self, v: List[str]) -> None:
    self._excludes = v

  @property
  def type(self) -> Set[ContextType]:
    return self._get_type()

  # XXX
  @overload
  def require_type(self, typ: Literal['apk']) -> APKContext: ...
  @overload
  def require_type(self, typ: ContextType) -> Context: ...
  def require_type(self, typ: ContextType) -> Any:
    if typ in self.type:
      return self
    from trueseeing.core.exc import InvalidContextError
    raise InvalidContextError()

  def store(self) -> Store:
    if self._store is None:
      assert self.wd is not None
      from trueseeing.core.store import Store
      self._store = Store(self.wd)
    return self._store

  def size_of(self) -> Optional[int]:
    return self._get_size()

  def fingerprint_of(self) -> str:
    return self._get_fingerprint()

  def remove(self) -> None:
    if os.path.exists(self.wd):
      from shutil import rmtree
      rmtree(self.wd)
    self._store = None

  def exists(self) -> bool:
    return os.path.isdir(self.wd)

  def create(self, exist_ok: bool = False) -> None:
    os.makedirs(self.wd, mode=0o700, exist_ok=exist_ok)

  def has_patches(self) -> bool:
    if self.exists():
      return self.store().query().patch_exists(None)
    else:
      return False

  def _get_identity(self) -> bytes:
    from os import stat
    c = stat(self._path)
    return f'0,{c.st_size},{c.st_mtime_ns}'.encode()

  def _get_analysis_flag_name(self, level: int) -> str:
    return f'.done{level}' if level < 4 else '.done'

  def get_analysis_level(self) -> int:
    for level in range(4, 0, -1):
      fn = os.path.join(self.wd, self._get_analysis_flag_name(level))
      if os.path.exists(fn):
        with open(fn, 'rb') as f:
          expected = f.read()
        if not expected:
          with open(fn, 'wb') as g:
            from trueseeing.core.ui import ui
            ui.warn('old style flags detected; marking them as for current target')
            g.write(self._get_identity())
          return level
        else:
          if expected == self._get_identity():
            return level
          else:
            return 0
    return 0

  def _mark_analysis_done(self, level: int) -> None:
    flagfn = self._get_analysis_flag_name(level)
    with open(os.path.join(self.wd, flagfn), 'wb') as f:
      f.write(self._get_identity())

  async def analyze(self, level: int = 4) -> Self:
    from trueseeing.core.ui import ui
    if self.get_analysis_level() >= level:
      await self._recheck_schema()
      ui.debug('analyzed once')
    else:
      if os.path.exists(self.wd):
        ui.info('analyze: removing leftover')
        self.remove()

      if level > 0:
        self.create()
        await self._analyze(level=level)
      else:
        self.invalidate()

      self._mark_analysis_done(level)
    return self

  def invalidate(self) -> None:
    for level in range(4, 0, -1):
      flag = os.path.join(self.wd, self._get_analysis_flag_name(level))
      if os.path.exists(flag):
        os.remove(flag)

  @abstractmethod
  def _get_workdir(self) -> str: ...

  @abstractmethod
  def _get_size(self) -> Optional[int]: ...

  @abstractmethod
  def _get_fingerprint(self) -> str: ...

  @abstractmethod
  def _get_type(self) -> Set[ContextType]: ...

  @abstractmethod
  async def _recheck_schema(self) -> None: ...

  @abstractmethod
  async def _analyze(self, level: int) -> None: ...

  async def _get_info(self, extended: bool) -> AsyncIterator[ContextInfo]:
    yield dict(path=self._path)
    size = self.size_of()
    if size:
      yield dict(size=size)
    yield dict(fp=self.fingerprint_of())
    yield dict(ctx=self.wd)
    yield dict(_patch=self.has_patches())
    yield dict(_analysis=self.get_analysis_level())

class Fingerprint:
  @cache
  def get(self, path: str) -> str:
    from hashlib import sha256
    with open(path, 'rb') as f:
      return sha256(f.read()).hexdigest()
