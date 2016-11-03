# Vulnerabilities:
# * Privacy: Tainted data en clair: logs
# * Privacy: IMEI/IMSI on the wire
# * Privacy: Tainted data en clair: the wire
# * Privacy: Tainted data en clair: permissive files
# * Privacy: Tainted data en clair: preferences
# * Privacy: Transmitting tainted data to questionable entity (country)

import logging

from trueseeing.flow.code import InvocationPattern
from trueseeing.flow.data import DataFlows
from trueseeing.signature.base import Detector, IssueSeverity, IssueConfidence

log = logging.getLogger(__name__)

class PrivacyDeviceIdDetector(Detector):
  option = 'privacy-device-id'

  def do_detect(self):
    with self.context.store() as store:
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;')):
        if DataFlows.solved_constant_data_in_invocation(store, op, 1) == 'android_id':
          yield self.issue(IssueSeverity.MAJOR, IssueConfidence.CERTAIN, store.query().qualname_of(op), 'privacy concerns: getting ANDROID_ID')
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/telephony/TelephonyManager;->getDeviceId\(\)Ljava/lang/String;')):
        yield self.issue(IssueSeverity.MAJOR, IssueConfidence.CERTAIN, store.query().qualname_of(op), 'privacy concerns: getting IMEI')
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/telephony/TelephonyManager;->getSubscriberId\(\)Ljava/lang/String;')):
        yield self.issue(IssueSeverity.MAJOR, IssueConfidence.CERTAIN, store.query().qualname_of(op), 'privacy concerns: getting IMSI')
