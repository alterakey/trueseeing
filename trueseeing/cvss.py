# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
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

import re
import math

class CVSS3Scoring:
  @staticmethod
  def severity_of(score):
    from trueseeing.issue import IssueSeverity
    if score <= 0.0:
      return IssueSeverity.INFO
    elif score < 4.0:
      return IssueSeverity.LOW
    elif score < 7.0:
      return IssueSeverity.MEDIUM
    elif score < 9.0:
      return IssueSeverity.HIGH
    else:
      return IssueSeverity.CRITICAL

  @staticmethod
  def temporalified(vec, confidence):
    from trueseeing.issue import IssueConfidence
    return '%sRC:%s/' % (vec, {IssueConfidence.CERTAIN:'C',IssueConfidence.FIRM:'R',IssueConfidence.TENTATIVE:'U'}[confidence])

  @staticmethod
  def score_of(vec):
    m = re.match(r'CVSS:3.0/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/S:(?P<S>[CU])/C:(?P<C>[HLN])/I:(?P<I>[HLN])/A:(?P<A>[HLN])(?:/RC:(?P<RC>[XCRU]))?/', vec)
    if m:
      def score(m):
        return temporal_score(m)

      def temporal_score(m):
        return roundup(base_score(m) * exploit_code_maturity_score(m) * remediation_level_score(m) * report_confidence_score(m))

      def exploit_code_maturity_score(m):
        return 1

      def remediation_level_score(m):
        return 1

      def report_confidence_score(m):
        M = dict(X=1.0, C=1.0, R=0.96, U=0.92)
        return M[m.group('RC')]

      def base_score(m):
        impact, exploitability = subscore_impact(m), subscore_exploitability(m)
        if impact <= 0:
          return 0
        else:
          if not scope_changed(m):
            return roundup(min(impact + exploitability, 10))
          else:
            return roundup(min(1.08 * (impact + exploitability), 10))

      def subscore_impact(m):
        base = subscore_impact_base(m)
        if not scope_changed(m):
          return 6.42 * base
        else:
          return 7.52*(base-0.029) - 3.25*(base-0.02)**15

      def subscore_impact_base(m):
        M = dict(N=0, L=0.22, H=0.56)
        C, I, A = M[m.group('C')], M[m.group('I')], M[m.group('A')]
        return 1 - ((1-C) * (1-I) * (1-A))

      def subscore_exploitability(m):
        M_AV = dict(N=0.85, A=0.62, L=0.55, P=0.2)
        M_AC = dict(L=0.77, H=0.44)
        M_PR = dict(N=0.85, L=0.68 if scope_changed(m) else 0.62, H=0.50 if scope_changed(m) else 0.27)
        M_UI = dict(N=0.85, R=0.62)
        AV, AC, PR, UI = M_AV[m.group('AV')], M_AC[m.group('AC')], M_PR[m.group('PR')], M_UI[m.group('UI')]

        return 8.22 * AV * AC * PR * UI

      def scope_changed(m):
        return (m.group('S') == 'C')

      def roundup(v):
        return math.ceil(v * 10.0) / 10.0

      return score(m)
    else:
      raise ValueError()
