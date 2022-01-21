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
from typing import TYPE_CHECKING, Optional

import attr

from trueseeing.core.cvss import CVSS3Scoring
from trueseeing.core.tools import noneif

if TYPE_CHECKING:
  from typing import List, Any
  from typing_extensions import Literal
  IssueSeverity = Literal['critical', 'high', 'medium', 'low', 'info']
  IssueConfidence = Literal['certain', 'firm', 'tentative']

@attr.s(auto_attribs=True)
class Issue:
  detector_id: str
  confidence: IssueConfidence
  cvss3_vector: str
  summary: str
  source: Optional[str] = None
  synopsis: Optional[str] = None
  description: Optional[str] = None
  seealso: Optional[str] = None
  solution: Optional[str] = None
  info1: Optional[str] = None
  info2: Optional[str] = None
  info3: Optional[str] = None
  row: Optional[str] = None
  col: Optional[str] = None
  cvss3_score: Optional[float] = None

  def __attrs_post_init__(self) -> None:
    self.cvss3_vector = CVSS3Scoring.temporalified(self.cvss3_vector, self.confidence)
    self.cvss3_score = noneif(self.cvss3_score, lambda: CVSS3Scoring.score_of(self.cvss3_vector))

  @staticmethod
  def from_analysis_issues_row(row: List[Any]) -> Issue:
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

  def severity(self) -> IssueSeverity:
    assert self.cvss3_score is not None
    return CVSS3Scoring.severity_of(self.cvss3_score)

  def brief_description(self) -> str:
    return ': '.join(filter(None, (self.summary, self.brief_info())))

  def brief_info(self) -> str:
    return ': '.join(filter(None, (self.info1, self.info2, self.info3)))
