from __future__ import annotations
from typing import TYPE_CHECKING, Optional

import attr

from trueseeing.core.cvss import CVSS3Scoring

if TYPE_CHECKING:
  from typing_extensions import Literal
  IssueSeverity = Literal['critical', 'high', 'medium', 'low', 'info']
  IssueConfidence = Literal['certain', 'firm', 'tentative']

@attr.s(auto_attribs=True, frozen=True)
class Issue:
  sigid: str
  cvss: str
  title: str
  cfd: IssueConfidence = 'firm'
  summary: Optional[str] = None
  desc: Optional[str] = None
  ref: Optional[str] = None
  sol: Optional[str] = None
  info0: Optional[str] = None
  info1: Optional[str] = None
  info2: Optional[str] = None
  aff0: Optional[str] = None
  aff1: Optional[str] = None
  aff2: Optional[str] = None

  @property
  def sev(self) -> IssueSeverity:
    return CVSS3Scoring.severity_of(self.score)

  @property
  def score(self) -> float:
    return CVSS3Scoring.score_of(self.cvss)

  def brief_desc(self) -> str:
    return ': '.join(filter(None, (self.title, self.brief_info())))

  def brief_info(self) -> str:
    return ': '.join(filter(None, (self.info0, self.info1, self.info2)))
