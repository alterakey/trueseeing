from __future__ import annotations
from typing import TYPE_CHECKING
from abc import ABC, abstractmethod

if TYPE_CHECKING:
  from collections import deque
  from typing import Any, TypedDict, Protocol, Optional, Callable, Coroutine, Union, List, Mapping
  from trueseeing.core.android.context import Context
  from trueseeing.core.model.issue import Issue

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

  class DetectorEntry(TypedDict):
    e: DetectorEntrypoint
    d: str

  CommandMap = Mapping[str, CommandEntry]
  CommandPatternMap = Mapping[str, CommandPatternEntry]
  OptionMap = Mapping[str, OptionEntry]
  ModifierMap = Mapping[str, ModifierEntry]
  DetectorMap = Mapping[str, DetectorEntry]

  class CommandHelper(Protocol):
    def get_target(self) -> Optional[str]: ...
    def require_target(self, msg: Optional[str] = None) -> str: ...
    def get_context(self) -> Context: ...
    async def get_context_analyzed(self, level: int = 3) -> Context: ...
    def decode_analysis_level(self, level: int) -> str: ...
    async def run(self, s: str) -> None: ...
    async def run_cmd(self, tokens: deque[str], line: Optional[str]) -> bool: ...
    def get_modifiers(self, args: deque[str]) -> List[str]: ...
    def get_effective_options(self, mods: List[str]) -> Mapping[str, str]: ...
    def get_graph_size_limit(self, mods: List[str]) -> Optional[int]: ...

  class DetectorHelper(Protocol):
    def get_context(self) -> Context: ...
    def raise_issue(self, issue: Issue) -> None: ...

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
  def get_options(self) -> OptionMap: ...

class Detector(ABC):
  @staticmethod
  @abstractmethod
  def create(helper: DetectorHelper) -> Detector: ...
  @abstractmethod
  def get_descriptor(self) -> DetectorMap: ...
