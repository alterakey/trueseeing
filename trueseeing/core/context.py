from __future__ import annotations
from typing import TYPE_CHECKING, overload

import os.path
from abc import ABC, abstractmethod
from trueseeing.core.env import get_cache_dir

if TYPE_CHECKING:
  from typing import List, Dict, Optional, Set, Literal, Any, Mapping, AsyncIterator, Tuple
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

  def _init_formats(self) -> None:
    from trueseeing.core.ext import Extension

    self._formats.update({
      'apk':dict(e=self._handle_apk, r=r'\.apk$', d='apk'),
    })

    for clazz in Extension.get().get_fileformathandlers():
      t = clazz.create()
      self._formats.update(t.get_formats())
      self._confbag.update(t.get_configs())

  def _handle_apk(self, path: str) -> Optional[Context]:
    from trueseeing.core.android.context import APKContext
    return APKContext(path)

class Context(ABC):
  _path: str
  _excludes: List[str]
  _store: Optional[Store] = None
  _wd: Optional[str] = None

  def __init__(self, path: str) -> None:
    self._path = path
    self._excludes = []
    # FIXME: is there a strict need of caching here?
    _ = self.wd

  @property
  def target(self) -> str:
    return self._path

  @property
  def wd(self) -> str:
    if self._wd is None:
      self._wd = self._workdir_of()
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

  def _workdir_of(self) -> str:
    return os.path.join(get_cache_dir(), self.fingerprint_of())

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

  def _get_analysis_flag_name(self, level: int) -> str:
    return f'.done{level}' if level < 4 else '.done'

  def get_analysis_level(self) -> int:
    for level in range(4, 0, -1):
      if os.path.exists(os.path.join(self.wd, self._get_analysis_flag_name(level))):
        return level
    return 0

  async def analyze(self, level: int = 4) -> Self:
    from trueseeing.core.ui import ui
    if self.get_analysis_level() >= level:
      await self._recheck_schema()
      ui.debug('analyzed once')
    else:
      flagfn = self._get_analysis_flag_name(level)
      if os.path.exists(self.wd):
        ui.info('analyze: removing leftover')
        self.remove()

      if level > 0:
        self.create()
        await self._analyze(level=level)

      with open(os.path.join(self.wd, flagfn), 'w'):
        pass
    return self

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

  async def _get_info(self) -> AsyncIterator[ContextInfo]:
    yield dict(path=self._path)
    size = self.size_of()
    if size:
      yield dict(size=size)
    yield dict(fp=self.fingerprint_of())
    yield dict(ctx=self.wd)
    yield dict(_patch=self.has_patches())
    yield dict(_analysis=self.get_analysis_level())
