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
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/telephony/TelephonyManager;->getLine1Number\(\)Ljava/lang/String;')):
        yield self.issue(IssueSeverity.MAJOR, IssueConfidence.CERTAIN, store.query().qualname_of(op), 'privacy concerns: getting phone number')
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/bluetooth/BluetoothAdapter;->getAddress\(\)Ljava/lang/String;')):
        yield self.issue(IssueSeverity.MAJOR, IssueConfidence.CERTAIN, store.query().qualname_of(op), 'privacy concerns: getting L2 address (Bluetooth)')
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/net/wifi/WifiInfo;->getMacAddress\(\)Ljava/lang/String;|Ljava/net/NetworkInterface;->getHardwareAddress\(\)')):
        yield self.issue(IssueSeverity.MAJOR, IssueConfidence.CERTAIN, store.query().qualname_of(op), 'privacy concerns: getting L2 address (Wi-Fi)')

class PrivacySMSDetector(Detector):
  option = 'privacy-sms'

  def do_detect(self):
    with self.context.store() as store:
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/net/Uri;->parse\(Ljava/lang/String;\)Landroid/net/Uri;')):
        try:
          if DataFlows.solved_constant_data_in_invocation(store, op, 0).startswith('content://sms/'):
            yield self.issue(IssueSeverity.MAJOR, IssueConfidence.CERTAIN, store.query().qualname_of(op), 'privacy concerns: accessing SMS')
        except DataFlows.NoSuchValueError:
          pass

      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/telephony/SmsMessage;->createFromPdu\(')):
        yield self.issue(IssueSeverity.MAJOR, IssueConfidence.FIRM, store.query().qualname_of(op), 'privacy concerns: intercepting incoming SMS')
