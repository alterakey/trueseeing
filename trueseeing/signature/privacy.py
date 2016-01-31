# Vulnerabilities:
# * Privacy: Tainted data en clair: logs
# * Privacy: IMEI/IMSI on the wire
# * Privacy: Tainted data en clair: the wire
# * Privacy: Tainted data en clair: permissive files
# * Privacy: Tainted data en clair: preferences
# * Privacy: Transmitting tainted data to questionable entity (country)

import logging

from trueseeing.signature.base import Detector, IssueSeverity, IssueConfidence

log = logging.getLogger(__name__)

class PrivacySensitiveDataFlowFileDetector(Detector):
  option = 'security-dataflow-file'

  def do_detect(self):
    yield self.issue(IssueSeverity.MAJOR, IssueConfidence.TENTATIVE, 'com/gmail/altakey/model/DeviceInfo.java', 'insecure data flow into file: IMEI/IMSI', row=24, col=0)

class PrivacySensitiveDataFlowWireDetector(Detector):
  option = 'security-dataflow-wire'

  def do_detect(self):
    yield self.issue(IssueSeverity.MAJOR, IssueConfidence.TENTATIVE, 'com/gmail/altakey/api/ApiClient.java', 'insecure data flow into wire: IMEI/IMSI', row=48, col=0)
