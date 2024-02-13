from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from typing import Protocol, List, Literal, overload, Any, Dict, Optional
  from trueseeing.api import FormatEntry
  from trueseeing.core.android.store import Store
  from trueseeing.core.android.context import APKContext

  ContextType = Literal['apk']

  class Context(Protocol):
    @property
    def wd(self) -> str: ...
    @property
    def target(self) -> str: ...
    @property
    def type(self) -> ContextType: ...
    @property
    def excludes(self) -> List[str]: ...
    @excludes.setter
    def excludes(self, v: List[str]) -> None: ...
    def fingerprint_of(self) -> str: ...
    def store(self) -> Store: ...
    def remove(self) -> None: ...
    def exists(self) -> bool: ...
    def create(self, exist_ok: bool = False) -> None: ...
    def has_patches(self) -> bool: ...
    def get_analysis_level(self) -> int: ...
    async def analyze(self, level: int = 3) -> None: ...
    @overload                                                        # type: ignore[misc]
    def require_type(self, typ: Literal['apk']) -> APKContext: ...
    def require_type(self, typ: ContextType) -> Any: ...

class FileOpener:
  _formats: Dict[str, FormatEntry]

  def __init__(self) -> None:
    from trueseeing.core.config import Configs
    self._confbag = Configs.get().bag
    self._formats = dict()
    self._init_formats()

  def get_context(self, path: str) -> Context:
    import re
    for k in sorted(self._formats.keys(), key=len, reverse=True):
      if not re.search(k, path, re.IGNORECASE):
        continue
      c = self._formats[k]['e'](path)
      if c is None:
        continue
      return c
    from trueseeing.core.exc import InvalidFileFormatError
    raise InvalidFileFormatError()

  def _init_formats(self) -> None:
    from trueseeing.core.ext import Extension

    self._formats.update({r'\.apk$':dict(e=self._handle_apk, d='apk')})

    for clazz in Extension.get().get_fileformathandlers():
      t = clazz.create()
      self._formats.update(t.get_formats())
      self._confbag.update(t.get_configs())

  def _handle_apk(self, path: str) -> Optional[Context]:
    from trueseeing.core.android.context import APKContext
    return APKContext(path, [])
