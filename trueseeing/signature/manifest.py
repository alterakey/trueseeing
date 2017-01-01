# Vulnerabilities:
# * Manifest: Open permissions
# * Manifest: Missing permissions
# * Manifest: Manual permissions (API < 16)
# * Manifest: Manipulatable ContentProvider (API < 9)
# * Manifest: Manipulatable Activity (API < 17)
# * Manifest: Manipulatable BroadcastReceiver
# * Manifest: Manipulatable backups
# * Manifest: Debuggable apps

import itertools
import logging

from trueseeing.signature.base import Detector, IssueSeverity, IssueConfidence, Issue

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
        source='AndroidManifest.xml'
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
        source='AndroidManifest.xml'
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
        source='AndroidManifest.xml'
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
        source='AndroidManifest.xml'
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
        source='AndroidManifest.xml'
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
        source='AndroidManifest.xml'
      )
