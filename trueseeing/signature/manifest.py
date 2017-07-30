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
# * Manifest: Open permissions
# * Manifest: Missing permissions (WIP)
# * Manifest: Manual permissions (API < 16) (WIP)
# * Manifest: Manipulatable ContentProvider (API < 9) (WIP: API version conditions)
# * Manifest: Manipulatable Activity
# * Manifest: Manipulatable BroadcastReceiver (WIP: API version conditions)
# * Manifest: Manipulatable backups
# * Manifest: Debuggable apps

import itertools
import logging

from trueseeing.signature.base import Detector
from trueseeing.issue import IssueConfidence, Issue

log = logging.getLogger(__name__)

class ManifestOpenPermissionDetector(Detector):
  option = 'manifest-open-permission'
  cvss = 'CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N/'

  def do_detect(self):
    # TBD: compare with actual permission needs
    yield from (
      Issue(
        detector_id=self.option,
        confidence=IssueConfidence.CERTAIN,
        cvss3_vector=self.cvss,
        summary='open permissions',
        info1=p,
        source='AndroidManifest.xml',
        synopsis="Application is requesting one or more permissions.",
        description="Application is requesting one or more permissions.  Permissions are an important security system of Android.  They control accesses to sensitive information (e.g. GPS, IMEI/IMSI, process stats, accounts, contacts, SMSs) or possibly dangerous/costly operation (e.g. SMSs, internet access, controlling system services, obstructing screens.)  Requesting ones are vital for proper functioning of application, though abusage leads to hurt privacy or device availability.  This issue is just an observation; requesting permissions alone does not constitute an security issue.",
      ) for p in self.context.permissions_declared())

class ManifestMissingPermissionDetector(Detector):
  option = 'manifest-missing-permission'
  cvss = 'CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def do_detect(self):
    # TBD: compare with actual permission needs
    pass

class ManifestManipActivity(Detector):
  option = 'manifest-manip-activity'
  cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def do_detect(self):
    yield from (
      Issue(
        detector_id=self.option,
        confidence=IssueConfidence.CERTAIN,
        cvss3_vector=self.cvss,
        summary='manipulatable Activity',
        info1=name,
        source='AndroidManifest.xml',
        synopsis="Application is exporting one or more activities.",
        description="Application is exporting one or more activities.  Activities are entrypoints to the application.  Exporting enables them to be invoked from other applications or system.  Unnecessary export increases attack surfaces.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.  This issue is just an observation; exporting activities alone does not constitute an security issue.",
        solution="Review them, and restrict access with application-specific permissions if necessary."
      ) for name in set(itertools.chain(
        self.context.parsed_manifest().getroot().xpath('//activity[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
        self.context.parsed_manifest().getroot().xpath('//activity[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
      )))

class ManifestManipBroadcastReceiver(Detector):
  option = 'manifest-manip-broadcastreceiver'
  cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def do_detect(self):
    yield from (
      Issue(
        detector_id=self.option,
        confidence=IssueConfidence.CERTAIN,
        cvss3_vector=self.cvss,
        summary='manipulatable BroadcastReceiver',
        info1=name,
        source='AndroidManifest.xml',
        synopsis="Application is exporting one or more broadcast receivers.",
        description="Application is exporting one or more broadcast receivers.  Broadcast receivers are system-wide event listeners of the application.  Exporting enables them to be invoked from other applications or system.  Unnecessary export increases attack surfaces.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.  This issue is just an observation; exporting broadcast receivers alone does not constitute an security issue.",
        solution="Review them and restrict access with application-specific permissions if necessary.  Consider the use of LocalBroadcastReceiver for ones that system-wide reachability is not needed."
      ) for name in set(itertools.chain(
        self.context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
        self.context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
      )))

class ManifestManipContentProvider(Detector):
  option = 'manifest-manip-contentprovider'
  cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def do_detect(self):
    yield from (
      Issue(
        detector_id=self.option,
        confidence=IssueConfidence.CERTAIN,
        cvss3_vector=self.cvss,
        summary='manipulatable ContentProvider',
        info1=name,
        source='AndroidManifest.xml',
        synopsis="Application is exporting one or more content providers.",
        description="Application is exporting one or more content providers.  Content providers defines REST/RDBMS-like IPC mechanism for the application.  Exporting enables them to be invoked from other applications or system.  Unnecessary export increases attack surfaces.  Please note that Android automatically exports them (API 8 or ealier) or ones with IntentFilter defined in the manifest (API level 9 or later).  This issue is just an observation; exporting content providers alone does not constitute an security issue.",
        solution='''\
Review them and explicitly unexport or restrict access with application-specific permissions if necessary.  To explicitly unexporting an content provider, define the following attribute to the <provider> tag in the manifest:

android:export="false"
'''
      ) for name in set(itertools.chain(
        self.context.parsed_manifest().getroot().xpath('//provider[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
        self.context.parsed_manifest().getroot().xpath('//provider[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
      )))

class ManifestManipBackup(Detector):
  option = 'manifest-manip-backup'
  cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/'

  def do_detect(self):
    if self.context.parsed_manifest().getroot().xpath('//application[not(@android:allowBackup="false")]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
      yield Issue(
        detector_id=self.option,
        confidence=IssueConfidence.CERTAIN,
        cvss3_vector=self.cvss,
        summary='manipulatable backups',
        source='AndroidManifest.xml',
        synopsis="Application data can be backed up and restored with the Full Backup feature.",
        description="Application data can be backed up and restored with the Full Backup feature, thusly making it subjectible to the backup attack.",
        solution='''\
Review them and opt-out from the Full Backup feature if necessary.  To opt-out, define the following attribute to the <application> tag in the manifest:

android:allowBackup="false"
'''
      )

class ManifestDebuggable(Detector):
  option = 'manifest-debuggable'
  cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/'

  def do_detect(self):
    if self.context.parsed_manifest().getroot().xpath('//application[@android:debuggable="true"]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
      yield Issue(
        detector_id=self.option,
        confidence=IssueConfidence.CERTAIN,
        cvss3_vector=self.cvss,
        summary='app is debuggable',
        source='AndroidManifest.xml',
        synopsis="Application can be debugged.",
        description="Application can be debugged (the debuggable bit is set.)  Debugging it gives attackers complete control of its process memory and control flow.",
        solution='''\
Disable the debuggable bit.  To disable it, define the following attribute to the <application> tag in the manifest:

android:debuggable="false"
'''
      )
