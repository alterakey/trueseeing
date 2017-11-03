# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
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

# Issues:
# * Privacy: Tainted data en clair: logs (WIP)
# * Privacy: IMEI/IMSI on the wire (WIP)
# * Privacy: Tainted data en clair: the wire (WIP)
# * Privacy: Tainted data en clair: permissive files (WIP)
# * Privacy: Tainted data en clair: preferences (WIP)
# * Privacy: Transmitting tainted data to questionable entity (country) (WIP)
# * Privacy: Getting device ID
# * Privacy: Accessing SMS functionality


import logging

import re

from trueseeing.flow.code import InvocationPattern
from trueseeing.flow.data import DataFlows
from trueseeing.signature.base import Detector
from trueseeing.issue import IssueConfidence, Issue

log = logging.getLogger(__name__)

class PrivacyDeviceIdDetector(Detector):
  option = 'privacy-device-id'
  description = 'Detects device fingerprinting behavior'
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N/'

  def analyzed(self, store, op):
    x = op.p[1].v
    if re.search('Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;', x):
      try:
        if DataFlows.solved_constant_data_in_invocation(store, op, 1) == 'android_id':
          return 'ANDROID_ID'
        else:
          return None
      except DataFlows.NoSuchValueError:
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
          yield Issue(
            detector_id=self.option,
            confidence=IssueConfidence.CERTAIN,
            cvss3_vector=self.cvss,
            summary='privacy concerns',
            info1='getting %s' % val_type,
            source=store.query().qualname_of(op)
          )

class PrivacySMSDetector(Detector):
  option = 'privacy-sms'
  description = 'Detects SMS-related behavior'
  cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/'

  def do_detect(self):
    with self.context.store() as store:
      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/net/Uri;->parse\(Ljava/lang/String;\)Landroid/net/Uri;')):
        try:
          if DataFlows.solved_constant_data_in_invocation(store, op, 0).startswith('content://sms/'):
            yield Issue(
              detector_id=self.option,
              confidence=IssueConfidence.CERTAIN,
              cvss3_vector=self.cvss,
              summary='privacy concerns',
              info1='accessing SMS',
              source=store.query().qualname_of(op)
            )
        except DataFlows.NoSuchValueError:
          pass

      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/telephony/SmsManager;->send')):
        yield Issue(
          detector_id=self.option,
          confidence=IssueConfidence.CERTAIN,
          cvss3_vector=self.cvss,
          summary='privacy concerns',
          info1='sending SMS',
          source=store.query().qualname_of(op)
        )

      for op in store.query().invocations(InvocationPattern('invoke-', 'Landroid/telephony/SmsMessage;->createFromPdu\(')):
        yield Issue(
          detector_id=self.option,
          confidence=IssueConfidence.FIRM,
          cvss3_vector=self.cvss,
          summary='privacy concerns',
          info1='intercepting incoming SMS',
          source=store.query().qualname_of(op)
        )
