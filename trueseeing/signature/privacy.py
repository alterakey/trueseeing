from __future__ import annotations
from typing import TYPE_CHECKING

import re

from trueseeing.core.code.model import InvocationPattern
from trueseeing.core.flow.data import DataFlows
from trueseeing.signature.base import Detector
from trueseeing.core.issue import Issue

if TYPE_CHECKING:
  from typing import Optional
  from trueseeing.core.store import Store
  from trueseeing.core.code.model import Op

class PrivacyDeviceIdDetector(Detector):
  option = 'privacy-device-id'
  description = 'Detects device fingerprinting behavior'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N/'
  _summary = 'privacy concerns'

  def analyzed(self, store: Store, op: Op) -> Optional[str]:
    x = op.p[1].v
    if re.search(r'Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;', x):
      try:
        if DataFlows.solved_constant_data_in_invocation(store, op, 1) == 'android_id':
          return 'ANDROID_ID'
        else:
          return None
      except DataFlows.NoSuchValueError:
        return None
    elif re.search(r'Landroid/telephony/TelephonyManager;->getDeviceId\(\)Ljava/lang/String;', x):
      return 'IMEI'
    elif re.search(r'Landroid/telephony/TelephonyManager;->getSubscriberId\(\)Ljava/lang/String;', x):
      return 'IMSI'
    elif re.search(r'Landroid/telephony/TelephonyManager;->getLine1Number\(\)Ljava/lang/String;', x):
      return 'phone number'
    elif re.search(r'Landroid/bluetooth/BluetoothAdapter;->getAddress\(\)Ljava/lang/String;', x):
      return 'L2 address (Bluetooth)'
    elif re.search(r'Landroid/net/wifi/WifiInfo;->getMacAddress\(\)Ljava/lang/String;|Ljava/net/NetworkInterface;->getHardwareAddress\(\)', x):
      return 'L2 address (Wi-Fi)'
    return None

  async def detect(self) -> None:
    with self._context.store() as store:
      for op in store.query().invocations(InvocationPattern('invoke-', r'Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;|Landroid/telephony/TelephonyManager;->getDeviceId\(\)Ljava/lang/String;|Landroid/telephony/TelephonyManager;->getSubscriberId\(\)Ljava/lang/String;|Landroid/telephony/TelephonyManager;->getLine1Number\(\)Ljava/lang/String;|Landroid/bluetooth/BluetoothAdapter;->getAddress\(\)Ljava/lang/String;|Landroid/net/wifi/WifiInfo;->getMacAddress\(\)Ljava/lang/String;|Ljava/net/NetworkInterface;->getHardwareAddress\(\)')):
        qn = store.query().qualname_of(op)
        if self._context.is_qualname_excluded(qn):
          continue
        val_type = self.analyzed(store, op)
        if val_type is not None:
          self._raise_issue(Issue(
            detector_id=self.option,
            confidence='certain',
            cvss3_vector=self._cvss,
            summary=self._summary,
            info1=f'getting {val_type}',
            source=store.query().qualname_of(op)
          ))

class PrivacySMSDetector(Detector):
  option = 'privacy-sms'
  description = 'Detects SMS-related behavior'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N/'
  _summary = 'privacy concerns'

  async def detect(self) -> None:
    with self._context.store() as store:
      for op in store.query().invocations(InvocationPattern('invoke-', r'Landroid/net/Uri;->parse\(Ljava/lang/String;\)Landroid/net/Uri;')):
        qn = store.query().qualname_of(op)
        if self._context.is_qualname_excluded(qn):
          continue
        try:
          if DataFlows.solved_constant_data_in_invocation(store, op, 0).startswith('content://sms/'):
            self._raise_issue(Issue(
              detector_id=self.option,
              confidence='certain',
              cvss3_vector=self._cvss,
              summary=self._summary,
              info1='accessing SMS',
              source=store.query().qualname_of(op)
            ))
        except DataFlows.NoSuchValueError:
          pass

      for op in store.query().invocations(InvocationPattern('invoke-', r'Landroid/telephony/SmsManager;->send')):
        qn = store.query().qualname_of(op)
        if self._context.is_qualname_excluded(qn):
          continue
        self._raise_issue(Issue(
          detector_id=self.option,
          confidence='certain',
          cvss3_vector=self._cvss,
          summary=self._summary,
          info1='sending SMS',
          source=store.query().qualname_of(op)
        ))

      for op in store.query().invocations(InvocationPattern('invoke-', r'Landroid/telephony/SmsMessage;->createFromPdu\(')):
        qn = store.query().qualname_of(op)
        if self._context.is_qualname_excluded(qn):
          continue
        self._raise_issue(Issue(
          detector_id=self.option,
          confidence='firm',
          cvss3_vector=self._cvss,
          summary=self._summary,
          info1='intercepting incoming SMS',
          source=store.query().qualname_of(op)
        ))
