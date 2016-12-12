# Vulnerabilities:
# * Privacy: Tainted data en clair: logs
# * Privacy: IMEI/IMSI on the wire
# * Privacy: Tainted data en clair: the wire
# * Privacy: Tainted data en clair: permissive files
# * Privacy: Tainted data en clair: preferences
# * Privacy: Transmitting tainted data to questionable entity (country)

import logging

import re

from trueseeing.flow.code import InvocationPattern
from trueseeing.flow.data import DataFlows
from trueseeing.signature.base import Detector, IssueSeverity, IssueConfidence

log = logging.getLogger(__name__)

class PrivacyDeviceIdDetector(Detector):
  option = 'privacy-device-id'
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N/'

  def analyzed(self, store, op):
    x = op.p[1].v
    if re.search('Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;', x):
      if DataFlows.solved_constant_data_in_invocation(store, op, 1) == 'android_id':
        return 'ANDROID_ID'
      else:
        return None
    elif re.search('Landroid/telephony/TelephonyManager;->getDeviceId\(\)Ljava/lang/String;', x):
      return 'IMEI'
    elif re.search('Landroid/telephony/TelephonyManager;->getSubscriberId\(\)Ljava/lang/String;', x):
      return 'IMSI'
    elif re.search('Landroid/telephony/TelephonyManager;->getLine1Number\(\)Ljava/lang/String;', x):
      return 'phone number'
    elif re.search('Landroid/bluetooth/BluetoothAdapter;->getAddress\(\)Ljava/lang/String;', x):
      return 'L2 address (Bluetooth)'
    elif re.search('Landroid/net/wifi/WifiInfo;->getMacAddress\(\)Ljava/lang/String;|Ljava/net/NetworkInterface;->getHardwareAddress\(\)', x):
      return 'L2 address (Wi-Fi)'

  def do_detect(self):
    with self.context.store() as store:
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;|Landroid/telephony/TelephonyManager;->getDeviceId\(\)Ljava/lang/String;|Landroid/telephony/TelephonyManager;->getSubscriberId\(\)Ljava/lang/String;|Landroid/telephony/TelephonyManager;->getLine1Number\(\)Ljava/lang/String;|Landroid/bluetooth/BluetoothAdapter;->getAddress\(\)Ljava/lang/String;|Landroid/net/wifi/WifiInfo;->getMacAddress\(\)Ljava/lang/String;|Ljava/net/NetworkInterface;->getHardwareAddress\(\)')):
        val_type = self.analyzed(store, op)
        if val_type is not None:
          yield self.issue(IssueConfidence.CERTAIN, self.cvss, 'privacy concerns', 'getting %s' % val_type, None, None, store.query().qualname_of(op))

class PrivacySMSDetector(Detector):
  option = 'privacy-sms'
  cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/'

  def do_detect(self):
    with self.context.store() as store:
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/net/Uri;->parse\(Ljava/lang/String;\)Landroid/net/Uri;')):
        try:
          if DataFlows.solved_constant_data_in_invocation(store, op, 0).startswith('content://sms/'):
            yield self.issue(IssueConfidence.CERTAIN, self.cvss, 'privacy concerns', 'accessing SMS', None, None, store.query().qualname_of(op))
        except DataFlows.NoSuchValueError:
          pass

      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/telephony/SmsManager;->send')):
        yield self.issue(IssueConfidence.CERTAIN, self.cvss, 'privacy concerns', 'sending SMS', None, None, store.query().qualname_of(op))

      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/telephony/SmsMessage;->createFromPdu\(')):
        yield self.issue(IssueConfidence.FIRM, self.cvss, 'privacy concerns', 'intercepting incoming SMS', None, None, store.query().qualname_of(op))
