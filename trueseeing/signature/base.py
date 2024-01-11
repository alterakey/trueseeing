from __future__ import annotations
from typing import TYPE_CHECKING

from abc import ABC, abstractmethod

from pubsub import pub

if TYPE_CHECKING:
  from typing import ClassVar
  from trueseeing.core.context import Context
  from trueseeing.core.issue import Issue

class Detector(ABC):
  option: ClassVar[str]
  description: ClassVar[str]

  _context: Context

  def __init__(self, context: Context) -> None:
    self._context = context

  def _raise_issue(self, issue: Issue) -> None:
    pub.sendMessage('issue', issue=issue)

  @abstractmethod
  async def detect(self) -> None: ...
