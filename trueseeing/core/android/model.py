from __future__ import annotations
from typing import TYPE_CHECKING, NamedTuple

from trueseeing.api import Signature

if TYPE_CHECKING:
  from typing import Optional, TypedDict, Dict, List
  from trueseeing.api import SignatureHelper, ConfigMap
  from trueseeing.core.android.context import APKContext
  from trueseeing.core.android.analyze.op import OpAnalyzer

  class XAPKSliceMember(TypedDict):
    id: str
    file: str

  class XAPKManifest(TypedDict, total=False):
    xapk_version: str
    total_size: int
    locales_name: Dict[str, str]
    split_apks: List[XAPKSliceMember]
    name: str
    icon: str
    package_name: str
    version_code: str
    version_name: str
    min_sdk_version: str
    target_sdk_version: str
    permissions: List[str]

  class Call(TypedDict):
    path: str
    sect: str
    offs: int
    priv: bool
    cpp: bool
    target: str

class Op(NamedTuple):
  addr: int
  l: str

class Token(NamedTuple):
  t: str
  v: str

class InvocationPattern(NamedTuple):
  insn: str
  value: str
  i: Optional[int] = None

class SignatureMixin(Signature):
  __an: Optional[OpAnalyzer] = None

  def __init__(self, helper: SignatureHelper) -> None:
    self._helper = helper

  def get_configs(self) -> ConfigMap:
    return dict()

  @property
  def _an(self) -> OpAnalyzer:
    if self.__an is None:
      from trueseeing.core.android.analyze.op import OpAnalyzer
      self.__an = OpAnalyzer()
    return self.__an

  def _get_context(self) -> APKContext:
    return self._helper.get_context().require_type('apk')
