from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.api import Detector

if TYPE_CHECKING:
  from trueseeing.api import DetectorHelper

class DetectorMixin(Detector):
  def __init__(self, helper: DetectorHelper) -> None:
    self._helper = helper
