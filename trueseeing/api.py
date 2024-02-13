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
  SignatureEntrypoint = Callable[[], Coroutine[Any, Any, None]]
  FormatHandlerEntrypoint = Callable[[str], Optional[Context]]
  ConfigGetterEntrypoint = Callable[[], Any]
  ConfigSetterEntrypoint = Callable[[Any], None]

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

  class ConfigEntry(TypedDict):
    g: ConfigGetterEntrypoint
    s: ConfigSetterEntrypoint
    n: str
    d: str

  class SignatureEntry(TypedDict):
    e: SignatureEntrypoint
    d: str

  class FormatEntry(TypedDict):
    e: FormatHandlerEntrypoint
    d: str

  CommandMap = Mapping[str, CommandEntry]
  CommandPatternMap = Mapping[str, CommandPatternEntry]
  OptionMap = Mapping[str, OptionEntry]
  ModifierMap = Mapping[str, ModifierEntry]
  ConfigMap = Mapping[str, ConfigEntry]
  SignatureMap = Mapping[str, SignatureEntry]
  FormatMap = Mapping[str, FormatEntry]

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
    def get_config(self, k: str) -> Any: ...
    def set_config(self, k: str, v: Any) -> None: ...

  class SignatureHelper(Protocol):
    @overload
    def get_context(self) -> Context: ...
    @overload
    def get_context(self, typ: Literal['apk']) -> APKContext: ...
    def get_context(self, typ: Optional[ContextType] = None) -> Any: ...
    def get_config(self, k: str) -> Any: ...
    def set_config(self, k: str, v: Any) -> None: ...
    def raise_issue(self, issue: Issue) -> None: ...
    def build_issue(
        self,
        sigid: str,
        cvss: str,
        title: str,
        cfd: IssueConfidence = 'firm',
        summary: Optional[str] = None,
        desc: Optional[str] = None,
        ref: Optional[str] = None,
        sol: Optional[str] = None,
        info0: Optional[str] = None,
        info1: Optional[str] = None,
        info2: Optional[str] = None,
        aff0: Optional[str] = None,
        aff1: Optional[str] = None,
        aff2: Optional[str] = None,
    ) -> Issue: ...


class FileFormatHandler(ABC):
  """File format handlers; they are responsible for opening path and create a valid Context."""

  @staticmethod
  @abstractmethod
  def create() -> FileFormatHandler:
    """Creates and return itself; This is because Python checks classes of concreteness only in their instantiation. e.g.

    return FooFileFormatHandler()
    """
    ...
  @abstractmethod
  def get_formats(self) -> FormatMap:
    """Creates and return format descriptor. Format descriptors are dicts comprise of:

    {"<path pattern>": dict(e=<entrypoint>, d="<description>")}

    e.g.:

    return {"\\.apk$": dict(e=self._handler, d="The Android Package File")}
    """
    ...
  @abstractmethod
  def get_configs(self) -> ConfigMap:
    """Creates and return the config descriptor it provides. Config descriptors are dicts comprise of:

    {"<name>": dict(g=<getter>, s=<setter>, n="<mnemonic>", d="<description>")}

    e.g.:

    return {
      'some_value':dict(g=self._getter, s=self._setter, n='some_value=value', d='config variable'),
    }
    """
    ...

class Command(ABC):
  """Commands; they provides one or more interactive mode commands."""

  @staticmethod
  @abstractmethod
  def create(helper: CommandHelper) -> Command:
    """Creates and return itself; This is because Python checks classes of concreteness only in their instantiation. e.g.

    return FooCommand(helper)
    """
    ...
  @abstractmethod
  def get_commands(self) -> CommandMap:
    """Creates and return the command descriptor it provides. Command descriptors are dicts comprise of:

    {"<cmd>": dict(e=<entrypoint>, n="<mnemonic>", d="<description>")}

    e.g.:

    return {
      "a": dict(e=self._analyze, n="a[a]", d="Analyze"),
      "aa": dict(e=self._analyze2),
    }
    """
    ...
  @abstractmethod
  def get_command_patterns(self) -> CommandPatternMap:
    """Creates and return the command pattern descriptor it provides. Command patterns are patterns that the first token (raw=False, the default) or whole command line (raw=True) should match. Entrypoints are called with tokens (raw=False) or whole command line (raw=True). Trailers are ignored while matching whole command line. Command pattern descriptors are dicts comprise of:

    {"<pattern>": dict(e=<entrypoint>, raw=<False|True>, n="<mnemonic>", d="<description>")}

    e.g.:

    return {
      "\\$[a-z0-9]+": dict(e=self._alias, n="$<name>[=<value>]", d="define alias"),
      '\\(.+\\)':dict(e=self._alias2, raw=True, n='(macro x y; cmd; cmd; ..)', d='define macro'),
    }
    """
    ...
  @abstractmethod
  def get_modifiers(self) -> ModifierMap:
    """Creates and return the modifier descriptor it recognizes. Modifier descriptors are dicts comprise of:

    {"<name>": dict(n="<mnemonic>", d="<description>")}

    e.g.:

    return {
      's':dict(n='@s:sig', d='include sig'),
      'x':dict(n='@x:pa.ckage.name', d='exclude package'),
    }
    """
    ...
  @abstractmethod
  def get_configs(self) -> ConfigMap:
    """Creates and return the config descriptor it provides. Config descriptors are dicts comprise of:

    {"<name>": dict(g=<getter>, s=<setter>, n="<mnemonic>", d="<description>")}

    e.g.:

    return {
      'some_value':dict(g=self._getter, s=self._setter, n='some_value=value', d='config variable'),
    }
    """
    ...
  @abstractmethod
  def get_options(self) -> OptionMap:
    """Creates and return the option descriptor it recognizes. Option descriptors are dicts comprise of:

    {"<name>": dict(n="<mnemonic>", d="<description>")}

    e.g.:

    return {
      'nocache':dict(n='nocache', d='do not replicate content before build [ca]')
    }
    """
    ...

class Signature(ABC):
  """Signatures; they provides one or more signatures for scanner."""

  @staticmethod
  @abstractmethod
  def create(helper: SignatureHelper) -> Signature:
    """Creates and return itself; This is because Python checks classes of concreteness only in their instantiation. e.g.

    return FooDetector(helper)
    """
    ...
  @abstractmethod
  def get_sigs(self) -> SignatureMap:
    """Creates and return signature descriptor. Signature descriptors are dicts comprise of:

    {"<signature id>": dict(e=<entrypoint>, d="<description>")}

    e.g.:

    return {"my-crypto-static-keys": dict(e=self._detect, d='Detects cryptographic function usage with static keys')}
    """
    ...
  @abstractmethod
  def get_configs(self) -> ConfigMap:
    """Creates and return the config descriptor it provides. Config descriptors are dicts comprise of:

    {"<name>": dict(g=<getter>, s=<setter>, n="<mnemonic>", d="<description>")}

    e.g.:

    return {
      'some_value':dict(g=self._getter, s=self._setter, n='some_value=value', d='config variable'),
    }
    """
    ...
