from __future__ import annotations
from typing import TYPE_CHECKING
from abc import ABC, abstractmethod

if TYPE_CHECKING:
  from collections import deque
  from typing import Any, TypedDict, Protocol, Optional, Callable, Coroutine, Union, List, Mapping, overload, Literal
  from trueseeing.core.context import Context, ContextType
  from trueseeing.core.android.context import APKContext
  from trueseeing.core.model.issue import Issue, IssueConfidence

  CommandEntrypoint = Callable[[deque[str]], Coroutine[Any, Any, None]]
  CommandlineEntrypoint = Callable[[str], Coroutine[Any, Any, None]]
  CommandPatternEntrypoints = Union[CommandEntrypoint, CommandlineEntrypoint]
  DetectorEntrypoint = Callable[[], Coroutine[Any, Any, None]]

  class Entry(TypedDict, total=False):
    e: CommandEntrypoint
    n: str
    d: str

  class CommandEntry(Entry):
    pass

  class CommandPatternEntry(CommandEntry, total=False):
    e: CommandPatternEntrypoints  # type: ignore[misc]
    raw: bool

  class OptionEntry(Entry):
    pass

  class ModifierEntry(Entry):
    pass

  class ConfigEntry(Entry):
    pass

  class DetectorEntry(TypedDict):
    e: DetectorEntrypoint
    d: str

  CommandMap = Mapping[str, CommandEntry]
  CommandPatternMap = Mapping[str, CommandPatternEntry]
  OptionMap = Mapping[str, OptionEntry]
  ModifierMap = Mapping[str, ModifierEntry]
  ConfigMap = Mapping[str, ConfigEntry]
  DetectorMap = Mapping[str, DetectorEntry]

  class CommandHelper(Protocol):
    def get_target(self) -> Optional[str]: ...
    def require_target(self, msg: Optional[str] = None) -> str: ...
    @overload
    def get_context(self) -> Context: ...
    @overload
    def get_context(self, typ: Literal['apk']) -> APKContext: ...
    def get_context(self, typ: Optional[ContextType] = None) -> Any: ...
    @overload
    async def get_context_analyzed(self, *, level: int = 3) -> APKContext: ...
    @overload
    async def get_context_analyzed(self, typ: Literal['apk'], *, level: int = 3) -> APKContext: ...
    async def get_context_analyzed(self, typ: Optional[ContextType] = None, *, level: int = 3) -> Any: ...
    def decode_analysis_level(self, level: int) -> str: ...
    async def run(self, s: str) -> None: ...
    async def run_cmd(self, tokens: deque[str], line: Optional[str]) -> bool: ...
    def get_modifiers(self, args: deque[str]) -> List[str]: ...
    def get_effective_options(self, mods: List[str]) -> Mapping[str, str]: ...
    def get_graph_size_limit(self, mods: List[str]) -> Optional[int]: ...

  class DetectorHelper(Protocol):
    @overload
    def get_context(self) -> Context: ...
    @overload
    def get_context(self, typ: Literal['apk']) -> APKContext: ...
    def get_context(self, typ: Optional[ContextType] = None) -> Any: ...
    def raise_issue(self, issue: Issue) -> None: ...
    def build_issue(
        self,
        detector_id: str,
        cvss_vector: str,
        confidence: IssueConfidence,
        summary: str,
        description: Optional[str] = None,
        seealso: Optional[str] = None,
        synopsis: Optional[str] = None,
        info1: Optional[str] = None,
        info2: Optional[str] = None,
        info3: Optional[str] = None,
        source: Optional[str] = None,
        row: Optional[str] = None,
        col: Optional[str] = None,
    ) -> Issue: ...


class Command(ABC):
  @staticmethod
  @abstractmethod
  def create(helper: CommandHelper) -> Command: ...
  @abstractmethod
  def get_commands(self) -> CommandMap: ...
  @abstractmethod
  def get_command_patterns(self) -> CommandPatternMap: ...
  @abstractmethod
  def get_modifiers(self) -> ModifierMap: ...
  @abstractmethod
  def get_configs(self) -> ConfigMap: ...
  @abstractmethod
  def get_options(self) -> OptionMap: ...

class Detector(ABC):
  @staticmethod
  @abstractmethod
  def create(helper: DetectorHelper) -> Detector: ...
  @abstractmethod
  def get_descriptor(self) -> DetectorMap: ...
