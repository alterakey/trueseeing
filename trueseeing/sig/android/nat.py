from __future__ import annotations
from typing import TYPE_CHECKING

import math
import re
from trueseeing.api import Signature
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Dict, AnyStr
  from trueseeing.api import SignatureMap, SignatureHelper, ConfigMap
  from trueseeing.core.android.context import APKContext
  from trueseeing.core.android.model import Call

class NativeCodeDetector(Signature):
  _cvss_info = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def __init__(self, helper: SignatureHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return NativeCodeDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {
      'nat-detect-api':dict(e=self._detect_api, d='Detects API call in native code'),
      'nat-detect-urls':dict(e=self._detect_url, d='Detects URL etc. in native code'),
    }

  def get_configs(self) -> ConfigMap:
    return dict()

  def _get_context(self) -> APKContext:
    return self._helper.get_context().require_type('apk')

  def _format_aff0(self, c: Call) -> str:
    return self._format_aff0_manual(c['path'], c['sect'], c['offs'])

  def _format_aff0_match(self, n: str, m: re.Match[AnyStr]) -> str:
    return self._format_aff0_manual(n, '', m.start())

  def _format_aff0_manual(self, n: str, s: str, o: int) -> str:
    return '{} ({}+{:08x})'.format(n, s, o)

  async def _detect_api(self) -> None:
    context = self._get_context()
    with context.store().query().scoped() as q:
      for c in q.calls():
        priv, target = c['priv'], c['target']
        self._helper.raise_issue(self._helper.build_issue(
          sigid='nat-detect-api',
          cvss=self._cvss_info,
          title='detected {} call'.format('private' if priv else 'API'),
          info0=target,
          aff0=self._format_aff0(c),
        ))

  async def _detect_url(self) -> None:
    from trueseeing.core.analyze import analyze_url_in
    context = self._get_context()
    with context.store().query().scoped() as q:
      for d in analyze_url_in(q.file_enum('lib/%', neg=True)):
        tentative = False
        if '...' in d['v']:
          ui.warn('truncated value found; disassemble again with wider fields', onetime=True)
          tentative = True
        self._helper.raise_issue(self._helper.build_issue(
          sigid='nat-detect-urls',
          cvss=self._cvss_info,
          title='detected {}'.format(d['typ']),
          cfd='tentative' if tentative else 'firm',
          info0=d['v'],
          aff0=d['fn'],
        ))

  @classmethod
  def _entropy_of(cls, string: str) -> float:
    o = 0.0
    m: Dict[str, int] = dict()
    for c in string:
      m[c] = m.get(c, 0) + 1
    for cnt in m.values():
      freq = float(cnt) / len(string)
      o -= freq * (math.log(freq) / math.log(2))
    return o

  @classmethod
  def _assumed_randomness_of(cls, string: str) -> float:
    try:
      return cls._entropy_of(string) / float(math.log(len(string)) / math.log(2))
    except ValueError:
      return 0
