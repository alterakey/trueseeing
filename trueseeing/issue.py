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

from trueseeing.cvss import CVSS3Scoring
from trueseeing.tools import noneif

class IssueSeverity:
  CRITICAL = 'critical'
  HIGH = 'high'
  MEDIUM = 'medium'
  LOW = 'low'
  INFO = 'info'

class IssueConfidence:
  CERTAIN = 'certain'
  FIRM = 'firm'
  TENTATIVE = 'tentative'

class Issue:
  def __init__(self, detector_id=None, confidence=None, cvss3_vector=None, source=None, summary=None, synopsis=None, description=None, seealso=None, solution=None, info1=None, info2=None, info3=None, row=None, col=None, cvss3_score=None):
    self.detector_id = detector_id
    self.confidence = confidence
    self.cvss3_vector = CVSS3Scoring.temporalified(cvss3_vector, confidence)
    self.source = source
    self.summary = summary
    self.synopsis = synopsis
    self.description = description
    self.seealso = seealso
    self.solution = solution
    self.info1 = info1
    self.info2 = info2
    self.info3 = info3
    self.row = row
    self.col = col
    self.cvss3_score = noneif(cvss3_score, lambda: CVSS3Scoring.score_of(self.cvss3_vector))

  @staticmethod
  def from_analysis_issues_row(row):
    map_ = [
      'detector_id',
      'summary',
      'synopsis',
      'description',
      'seealso',
      'solution',
      'info1',
      'info2',
      'info3',
      'confidence',
      'cvss3_score',
      'cvss3_vector',
      'source',
      'row',
      'col'
    ]
    return Issue(**{k:row[map_.index(k)] for k in map_})

  def severity(self):
    return CVSS3Scoring.severity_of(self.cvss3_score)

  def brief_description(self):
    return ': '.join(filter(None, (self.summary, self.brief_info())))

  def brief_info(self):
    return ': '.join(filter(None, (self.info1, self.info2, self.info3)))
