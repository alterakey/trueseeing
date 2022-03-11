# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <altakey@gmail.com>
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

from __future__ import annotations
from typing import TYPE_CHECKING

import itertools
import re
import os

from pubsub import pub

from trueseeing.signature.base import Detector
from trueseeing.core.issue import Issue

if TYPE_CHECKING:
  pass

class ManifestOpenPermissionDetector(Detector):
  option = 'manifest-open-permission'
  description = 'Detects declarated permissions'
  _cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N/'

  async def detect(self) -> None:
    # TBD: compare with actual permission needs
    for p in self._context.permissions_declared():
      pub.sendMessage('issue', issue=Issue(
        detector_id=self.option,
        confidence='certain',
        cvss3_vector=self._cvss,
        summary='open permissions',
        info1=p,
        source='AndroidManifest.xml',
        synopsis="Application is requesting one or more permissions.",
        description="Application is requesting one or more permissions.  Permissions are an important security system of Android.  They control accesses to sensitive information (e.g. GPS, IMEI/IMSI, process stats, accounts, contacts, SMSs) or possibly dangerous/costly operation (e.g. SMSs, internet access, controlling system services, obstructing screens.)  Requesting ones are vital for proper functioning of application, though abusage leads to hurt privacy or device availability.  This issue is just an observation; requesting permissions alone does not constitute an security issue.",
      ))

class ComponentNamePolicy:
  def __init__(self) -> None:
    import pkg_resources
    with open(pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'tlds.txt')), 'r', encoding='utf-8') as f:
      self._re_tlds = re.compile('^(?:{})$'.format('|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#'))), flags=re.IGNORECASE)

  def looks_public(self, name: str) -> bool:
    if '.' in name:
      gtld = name.split('.')[0]
      return (gtld == 'android') or ('.intent.action.' in name) or bool(self._re_tlds.search(gtld))
    else:
      return False

class ManifestManipActivity(Detector):
  option = 'manifest-manip-activity'
  description = 'Detects exported Activity'
  _cvss1 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss2 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/'

  async def detect(self) -> None:
    policy = ComponentNamePolicy()
    ns = dict(android='http://schemas.android.com/apk/res/android')

    for name in set(itertools.chain(
        self._context.parsed_manifest().getroot().xpath('//activity[not(@android:permission)]/intent-filter/../@android:name', namespaces=ns),
        self._context.parsed_manifest().getroot().xpath('//activity[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=ns),
    )):
      filter_ = [name for name in self._context.parsed_manifest().getroot().xpath(f'//activity[@android:name="{name}"]/intent-filter/action/@android:name', namespaces=ns) if not policy.looks_public(name)]
      if not filter_:
        pub.sendMessage('issue', issue=Issue(
          detector_id=self.option,
          confidence='certain',
          cvss3_vector=self._cvss1,
          summary='manipulatable Activity',
          info1=name,
          source='AndroidManifest.xml',
          synopsis="Application is exporting one or more activities.",
          description="Application is exporting one or more activities.  Activities are entrypoints to the application.  Exporting enables them to be invoked from other applications or system.  Unnecessary export increases attack surfaces.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.  This issue is just an observation; exporting activities alone does not constitute an security issue.",
          solution="Review them, and restrict access with application-specific permissions if necessary."
        ))
      else:
        pub.sendMessage('issue', issue=Issue(
          detector_id=self.option,
          confidence='certain',
          cvss3_vector=self._cvss2,
          summary='manipulatable Activity with private action names',
          info1=name,
          info2=', '.join(filter_),
          source='AndroidManifest.xml',
          synopsis="Application is exporting one or more activities using seemingly private action names, suggesting inadvent export.",
          description="Application is exporting one or more activities using seemingly private action names, suggesting inadvent export.  Activities are entrypoints to the application.  Exporting enables them to be invoked from other applications or system.  Inadvent exporting enables malwares or malicious users to manipulate the application.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.",
          solution="Review them, and restrict access with application-specific permissions if necessary."
        ))

class ManifestManipBroadcastReceiver(Detector):
  option = 'manifest-manip-broadcastreceiver'
  description = 'Detects exported BroadcastReceiver'
  _cvss1 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss2 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/'

  async def detect(self) -> None:
    policy = ComponentNamePolicy()
    ns = dict(android='http://schemas.android.com/apk/res/android')

    for name in set(itertools.chain(
        self._context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission)]/intent-filter/../@android:name', namespaces=ns),
        self._context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=ns),
    )):
      filter_ = [name for name in self._context.parsed_manifest().getroot().xpath(f'//receiver[@android:name="{name}"]/intent-filter/action/@android:name', namespaces=ns) if not policy.looks_public(name)]
      if not filter_:
        pub.sendMessage('issue', issue=Issue(
          detector_id=self.option,
          confidence='certain',
          cvss3_vector=self._cvss1,
          summary='manipulatable BroadcastReceiver',
          info1=name,
          source='AndroidManifest.xml',
          synopsis="Application is exporting one or more broadcast receivers.",
          description="Application is exporting one or more broadcast receivers.  Broadcast receivers are system-wide event listeners of the application.  Exporting enables them to be invoked from other applications or system.  Unnecessary export increases attack surfaces.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.  This issue is just an observation; exporting broadcast receivers alone does not constitute an security issue.",
          solution="Review them and restrict access with application-specific permissions if necessary.  Consider the use of LocalBroadcastReceiver for ones that system-wide reachability is not needed."
        ))
      else:
        pub.sendMessage('issue', issue=Issue(
          detector_id=self.option,
          confidence='certain',
          cvss3_vector=self._cvss2,
          summary='manipulatable BroadcastReceiver with private action names',
          info1=name,
          info2=', '.join(filter_),
          source='AndroidManifest.xml',
          synopsis="Application is exporting one or more broadcast receivers using seemingly private action names, suggesting inadvent export.",
          description="Application is exporting one or more broadcast receivers using seemingly private action names, suggesting inadvent export.  Broadcast receivers are system-wide event listeners of the application.  Exporting enables them to be invoked from other applications or system.  Inadvent exporting enables malwares or malicious users to manipulate the application.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.",
          solution="Review them, and restrict access with application-specific permissions if necessary."
        ))

class ManifestManipContentProvider(Detector):
  option = 'manifest-manip-contentprovider'
  description = 'Detects exported ContentProvider'
  _cvss1 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss2 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/'

  async def detect(self) -> None:
    policy = ComponentNamePolicy()
    ns = dict(android='http://schemas.android.com/apk/res/android')

    for name in set(itertools.chain(
        self._context.parsed_manifest().getroot().xpath('//provider[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
        self._context.parsed_manifest().getroot().xpath('//provider[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
    )):
      filter_ = [name for name in self._context.parsed_manifest().getroot().xpath(f'//receiver[@android:name="{name}"]/intent-filter/action/@android:name', namespaces=ns) if not policy.looks_public(name)]
      if not filter_:
        pub.sendMessage('issue', issue=Issue(
          detector_id=self.option,
          confidence='certain',
          cvss3_vector=self._cvss1,
          summary='manipulatable ContentProvider',
          info1=name,
          source='AndroidManifest.xml',
          synopsis="Application is exporting one or more content providers.",
          description="Application is exporting one or more content providers.  Content providers defines REST/RDBMS-like IPC mechanism for the application.  Exporting enables them to be invoked from other applications or system.  Unnecessary export increases attack surfaces.  Please note that Android automatically exports them (API 8 or ealier) or ones with IntentFilter defined in the manifest (API level 9 or later).  This issue is just an observation; exporting content providers alone does not constitute an security issue.",
          solution='''\
  Review them and explicitly unexport or restrict access with application-specific permissions if necessary.  To explicitly unexporting an content provider, define the following attribute to the <provider> tag in the manifest:

  android:export="false"
  '''
        ))
      else:
        pub.sendMessage('issue', issue=Issue(
          detector_id=self.option,
          confidence='certain',
          cvss3_vector=self._cvss2,
          summary='manipulatable ContentProvider with private action names',
          info1=name,
          info2=', '.join(filter_),
          source='AndroidManifest.xml',
          synopsis="Application is exporting one or more content providers using seemingly private action names, suggesting inadvent export.",
          description="Application is exporting one or more content providers using seemingly private action names, suggesting inadvent export.  Content providers defines REST/RDBMS-like IPC mechanism for the application.  Exporting enables them to be invoked from other applications or system.  Inadvent exporting enables malwares or malicious users to manipulate the application.  Please note that Android automatically exports them (API 8 or ealier) or ones with IntentFilter defined in the manifest (API level 9 or later).",
          solution='''\
  Review them and explicitly unexport or restrict access with application-specific permissions if necessary.  To explicitly unexporting an content provider, define the following attribute to the <provider> tag in the manifest:

  android:export="false"
  '''
        ))

class ManifestManipBackup(Detector):
  option = 'manifest-manip-backup'
  description = 'Detects enabled backup bit'
  _cvss = 'CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/'

  async def detect(self) -> None:
    if self._context.parsed_manifest().getroot().xpath('//application[not(@android:allowBackup="false")]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
      pub.sendMessage('issue', issue=Issue(
        detector_id=self.option,
        confidence='certain',
        cvss3_vector=self._cvss,
        summary='manipulatable backups',
        source='AndroidManifest.xml',
        synopsis="Application data can be backed up and restored with the Full Backup feature.",
        description="Application data can be backed up and restored with the Full Backup feature, thusly making it subjectible to the backup attack.",
        solution='''\
Review them and opt-out from the Full Backup feature if necessary.  To opt-out, define the following attribute to the <application> tag in the manifest:

android:allowBackup="false"
'''
      ))

class ManifestDebuggable(Detector):
  option = 'manifest-debuggable'
  description = 'Detects enabled debug bits'
  _cvss = 'CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/'

  async def detect(self) -> None:
    if self._context.parsed_manifest().getroot().xpath('//application[@android:debuggable="true"]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
      pub.sendMessage('issue', issue=Issue(
        detector_id=self.option,
        confidence='certain',
        cvss3_vector=self._cvss,
        summary='app is debuggable',
        source='AndroidManifest.xml',
        synopsis="Application can be debugged.",
        description="Application can be debugged (the debuggable bit is set.)  Debugging it gives attackers complete control of its process memory and control flow.",
        solution='''\
Disable the debuggable bit.  To disable it, define the following attribute to the <application> tag in the manifest:

android:debuggable="false"
'''
      ))
