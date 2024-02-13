from __future__ import annotations
from typing import TYPE_CHECKING

import re

from trueseeing.core.android.model.code import InvocationPattern
from trueseeing.core.android.analysis.flow import DataFlow
from trueseeing.core.model.sig import SignatureMixin

if TYPE_CHECKING:
  from typing import Optional
  from trueseeing.core.android.db import Query
  from trueseeing.core.android.model.code import Op
  from trueseeing.api import Signature, SignatureHelper, SignatureMap

class PrivacyDeviceIdDetector(SignatureMixin):
  _id = 'privacy-device-id'
  description = 'Detects device fingerprinting behavior'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N/'
  _summary = 'privacy concerns'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return PrivacyDeviceIdDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects device fingerprinting behavior')}

  def analyzed(self, q: Query, op: Op) -> Optional[str]:
    x = op.p[1].v
    if re.search(r'Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;', x):
      try:
        if DataFlow(q).solved_constant_data_in_invocation(op, 1) == 'android_id':
          return 'ANDROID_ID'
        else:
          return None
      except DataFlow.NoSuchValueError:
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
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain',
          cvss=self._cvss,
          title=self._summary,
          info0=f'getting {val_type}',
          aff0=q.qualname_of(op)
        ))

class PrivacySMSDetector(SignatureMixin):
  _id = 'privacy-sms'
  _cvss = 'CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N/'
  _summary = 'privacy concerns'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return PrivacySMSDetector(helper)

  def get_sigs(self) -> SignatureMap:
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
        if DataFlow(q).solved_constant_data_in_invocation(op, 0).startswith('content://sms/'):
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cfd='certain',
            cvss=self._cvss,
            title=self._summary,
            info0='accessing SMS',
            aff0=q.qualname_of(op)
          ))
      except DataFlow.NoSuchValueError:
        pass

    for op in q.invocations(InvocationPattern('invoke-', r'Landroid/telephony/SmsManager;->send')):
      qn = q.qualname_of(op)
      if context.is_qualname_excluded(qn):
        continue
      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cfd='certain',
        cvss=self._cvss,
        title=self._summary,
        info0='sending SMS',
        aff0=q.qualname_of(op)
      ))

    for op in q.invocations(InvocationPattern('invoke-', r'Landroid/telephony/SmsMessage;->createFromPdu\(')):
      qn = q.qualname_of(op)
      if context.is_qualname_excluded(qn):
        continue
      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cvss=self._cvss,
        title=self._summary,
        info0='intercepting incoming SMS',
        aff0=q.qualname_of(op)
      ))
