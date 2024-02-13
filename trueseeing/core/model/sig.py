from __future__ import annotations
from typing import TYPE_CHECKING

from trueseeing.api import Signature

if TYPE_CHECKING:
  from trueseeing.api import SignatureHelper, ConfigMap

class SignatureMixin(Signature):
  def __init__(self, helper: SignatureHelper) -> None:
    self._helper = helper

  def get_configs(self) -> ConfigMap:
    return dict()
