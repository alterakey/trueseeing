# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <altakey@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations
from typing import TYPE_CHECKING

import re

if TYPE_CHECKING:
  from trueseeing.core.issue import IssueSeverity, IssueConfidence

class CVSS3Scoring:
  def __init__(self, m: re.Match[str]):
    self._m = m

  @classmethod
  def severity_of(cls, score: float) -> IssueSeverity:
    if score <= 0.0:
      return 'info'
    elif score < 4.0:
      return 'low'
    elif score < 7.0:
      return 'medium'
    elif score < 9.0:
      return 'high'
    else:
      return 'critical'

  @classmethod
  def temporalified(cls, vec: str, confidence: IssueConfidence) -> str:
    return '{v}RC:{c}/'.format(
      v=vec,
      c={'certain':'C','firm':'R','tentative':'U'}[confidence]
    )

  @classmethod
  def score_of(cls, vec: str) -> float:
    m = re.match(r'CVSS:3.0/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/S:(?P<S>[CU])/C:(?P<C>[HLN])/I:(?P<I>[HLN])/A:(?P<A>[HLN])(?:/RC:(?P<RC>[XCRU]))?/', vec)
    if m:
      return cls(m)._score()
    else:
      raise ValueError()

  def _score(self) -> float:
    return self._temporal_score()

  def _temporal_score(self) -> float:
    return self._roundup(self._base_score() * self._exploit_code_maturity_score() * self._remediation_level_score() * self._report_confidence_score())

  def _exploit_code_maturity_score(self) -> float:
    return 1

  def _remediation_level_score(self) -> float:
    return 1

  def _report_confidence_score(self) -> float:
    M = dict(X=1.0, C=1.0, R=0.96, U=0.92)
    return M[self._m.group('RC')]

  def _base_score(self) -> float:
    impact, exploitability = self._subscore_impact(), self._subscore_exploitability()
    if impact <= 0:
      return 0
    else:
      if not self._scope_changed():
        return self._roundup(min(impact + exploitability, 10))
      else:
        return self._roundup(min(1.08 * (impact + exploitability), 10))

  def _subscore_impact(self) -> float:
    base = self._subscore_impact_base()
    if not self._scope_changed():
      return 6.42 * base
    else:
      return 7.52*(base-0.029) - 3.25*(base-0.02)**15

  def _subscore_impact_base(self) -> float:
    M = dict(N=0, L=0.22, H=0.56)
    C, I, A = M[self._m.group('C')], M[self._m.group('I')], M[self._m.group('A')]
    return 1 - ((1-C) * (1-I) * (1-A))

  def _subscore_exploitability(self) -> float:
    M_AV = dict(N=0.85, A=0.62, L=0.55, P=0.2)
    M_AC = dict(L=0.77, H=0.44)
    M_PR = dict(N=0.85, L=0.68 if self._scope_changed() else 0.62, H=0.50 if self._scope_changed() else 0.27)
    M_UI = dict(N=0.85, R=0.62)
    AV, AC, PR, UI = M_AV[self._m.group('AV')], M_AC[self._m.group('AC')], M_PR[self._m.group('PR')], M_UI[self._m.group('UI')]

    return 8.22 * AV * AC * PR * UI

  def _scope_changed(self) -> bool:
    return (self._m.group('S') == 'C')

  @classmethod
  def _roundup(cls, v: float) -> float:
    from math import ceil
    return ceil(v * 10.0) / 10.0
