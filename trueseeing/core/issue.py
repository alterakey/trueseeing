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
import attr

from trueseeing.core.cvss import CVSS3Scoring
from trueseeing.core.tools import noneif

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

@attr.s
class Issue:
  detector_id = attr.ib(default=None)
  confidence = attr.ib(default=None)
  cvss3_vector = attr.ib(default=None)
  source = attr.ib(default=None)
  summary = attr.ib(default=None)
  synopsis = attr.ib(default=None)
  description = attr.ib(default=None)
  seealso = attr.ib(default=None)
  solution = attr.ib(default=None)
  info1 = attr.ib(default=None)
  info2 = attr.ib(default=None)
  info3 = attr.ib(default=None)
  row = attr.ib(default=None)
  col = attr.ib(default=None)
  cvss3_score = attr.ib(default=None)

  def __attrs_post_init__(self):
    self.cvss3_vector = CVSS3Scoring.temporalified(self.cvss3_vector, self.confidence)
    self.cvss3_score = noneif(self.cvss3_score, lambda: CVSS3Scoring.score_of(self.cvss3_vector))

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
