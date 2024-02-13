from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from typing import ClassVar, Dict, Optional
  from trueseeing.api import ConfigEntry

class Configs:
  _i: ClassVar[Optional[Configs]] = None
  _bag: Dict[str, ConfigEntry]

  def __init__(self) -> None:
    self._bag = dict()

  @classmethod
  def get(cls) -> Configs:
    if not cls._i:
      cls._i = Configs()
    return cls._i

  @property
  def bag(self) -> Dict[str, ConfigEntry]:
    return self._bag
