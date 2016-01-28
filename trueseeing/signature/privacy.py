# Vulnerabilities:
# * Privacy: Tainted data en clair: logs
# * Privacy: IMEI/IMSI on the wire
# * Privacy: Tainted data en clair: the wire
# * Privacy: Tainted data en clair: permissive files
# * Privacy: Tainted data en clair: preferences
# * Privacy: Transmitting tainted data to questionable entity (country)

import logging

from trueseeing.signature.base import Detector

log = logging.getLogger(__name__)

class PrivacySensitiveDataFlowFileDetector(Detector):
  options = 'security-dataflow-file'

  def do_detect(self):
    yield self.warning_on(name='com/gmail/altakey/model/DeviceInfo.java', row=24, col=0, desc='insecure data flow into file: IMEI/IMSI', opt='-Wsecurity-dataflow-file')

class PrivacySensitiveDataFlowWireDetector(Detector):
  options = 'security-dataflow-wire'

  def do_detect(self):
    yield self.warning_on(name='com/gmail/altakey/api/ApiClient.java', row=48, col=0, desc='insecure data flow on wire: IMEI/IMSI', opt='-Wsecurity-dataflow-wire')
