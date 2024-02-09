from __future__ import annotations
from typing import TYPE_CHECKING

import re

from trueseeing.core.android.model.code import InvocationPattern
from trueseeing.core.android.analysis.flow import DataFlows
from trueseeing.core.model.sig import DetectorMixin
from trueseeing.core.model.issue import Issue

if TYPE_CHECKING:
  from typing import Optional
  from trueseeing.core.android.db import Query
  from trueseeing.core.android.model.code import Op
  from trueseeing.api import Detector, DetectorHelper, DetectorMap

class PrivacyDeviceIdDetector(DetectorMixin):
  _id = 'privacy-device-id'
  description = 'Detects device fingerprinting behavior'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N/'
  _summary = 'privacy concerns'

  @staticmethod
  def create(helper: DetectorHelper) -> Detector:
    return PrivacyDeviceIdDetector(helper)

  def get_descriptor(self) -> DetectorMap:
    return {self._id:dict(e=self.detect, d='Detects device fingerprinting behavior')}

  def analyzed(self, q: Query, op: Op) -> Optional[str]:
    x = op.p[1].v
    if re.search(r'Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;', x):
      try:
        if DataFlows.solved_constant_data_in_invocation(q, op, 1) == 'android_id':
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
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for op in q.invocations(InvocationPattern('invoke-', r'Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;|Landroid/telephony/TelephonyManager;->getDeviceId\(\)Ljava/lang/String;|Landroid/telephony/TelephonyManager;->getSubscriberId\(\)Ljava/lang/String;|Landroid/telephony/TelephonyManager;->getLine1Number\(\)Ljava/lang/String;|Landroid/bluetooth/BluetoothAdapter;->getAddress\(\)Ljava/lang/String;|Landroid/net/wifi/WifiInfo;->getMacAddress\(\)Ljava/lang/String;|Ljava/net/NetworkInterface;->getHardwareAddress\(\)')):
      qn = q.qualname_of(op)
      if context.is_qualname_excluded(qn):
        continue
      val_type = self.analyzed(q, op)
      if val_type is not None:
        self._helper.raise_issue(Issue(
          detector_id=self._id,
          confidence='certain',
          cvss3_vector=self._cvss,
          summary=self._summary,
          info1=f'getting {val_type}',
          source=q.qualname_of(op)
        ))

class PrivacySMSDetector(DetectorMixin):
  _id = 'privacy-sms'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N/'
  _summary = 'privacy concerns'

  @staticmethod
  def create(helper: DetectorHelper) -> Detector:
    return PrivacySMSDetector(helper)

  def get_descriptor(self) -> DetectorMap:
    return {self._id:dict(e=self.detect, d='Detects SMS-related behavior')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for op in q.invocations(InvocationPattern('invoke-', r'Landroid/net/Uri;->parse\(Ljava/lang/String;\)Landroid/net/Uri;')):
      qn = q.qualname_of(op)
      if context.is_qualname_excluded(qn):
        continue
      try:
        if DataFlows.solved_constant_data_in_invocation(q, op, 0).startswith('content://sms/'):
          self._helper.raise_issue(Issue(
            detector_id=self._id,
            confidence='certain',
            cvss3_vector=self._cvss,
            summary=self._summary,
            info1='accessing SMS',
            source=q.qualname_of(op)
          ))
      except DataFlows.NoSuchValueError:
        pass

    for op in q.invocations(InvocationPattern('invoke-', r'Landroid/telephony/SmsManager;->send')):
      qn = q.qualname_of(op)
      if context.is_qualname_excluded(qn):
        continue
      self._helper.raise_issue(Issue(
        detector_id=self._id,
        confidence='certain',
        cvss3_vector=self._cvss,
        summary=self._summary,
        info1='sending SMS',
        source=q.qualname_of(op)
      ))

    for op in q.invocations(InvocationPattern('invoke-', r'Landroid/telephony/SmsMessage;->createFromPdu\(')):
      qn = q.qualname_of(op)
      if context.is_qualname_excluded(qn):
        continue
      self._helper.raise_issue(Issue(
        detector_id=self._id,
        confidence='firm',
        cvss3_vector=self._cvss,
        summary=self._summary,
        info1='intercepting incoming SMS',
        source=q.qualname_of(op)
      ))
