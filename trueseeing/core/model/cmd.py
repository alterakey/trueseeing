from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from typing import Dict, Any, TypedDict
  from trueseeing.app.inspect import Runner

  class Entry(TypedDict, total=False):
    e: Any
    n: str
    d: str

  class CommandEntry(Entry):
    pass

  class CommandPatternEntry(CommandEntry, total=False):
    raw: bool

  class OptionEntry(Entry):
    pass

  class ModifierEntry(Entry):
    pass

class Command:
  def __init__(self, runner: Runner) -> None:
    pass
  def get_commands(self) -> Dict[str, CommandEntry]:
    return dict()
  def get_command_patterns(self) -> Dict[str, CommandPatternEntry]:
    return dict()
  def get_modifiers(self) -> Dict[str, ModifierEntry]:
    return dict()
  def get_options(self) -> Dict[str, OptionEntry]:
    return dict()
