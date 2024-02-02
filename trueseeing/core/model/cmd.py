from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.api import Command

if TYPE_CHECKING:
  from trueseeing.api import CommandMap, CommandPatternMap, ModifierMap, OptionMap, ConfigMap

class CommandMixin(Command):
  def get_commands(self) -> CommandMap:
    return dict()
  def get_command_patterns(self) -> CommandPatternMap:
    return dict()
  def get_modifiers(self) -> ModifierMap:
    return dict()
  def get_configs(self) -> ConfigMap:
    return dict()
  def get_options(self) -> OptionMap:
    return dict()
