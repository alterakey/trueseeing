# Vulnerabilities:
# * Manifest: Open permissions
# * Manifest: Missing permissions
# * Manifest: Manual permissions (API < 16)
# * Manifest: Manipulatable ContentProvider (API < 9)
# * Manifest: Manipulatable Activity (API < 17)
# * Manifest: Manipulatable BroadcastReceiver
# * Manifest: Manipulatable backups

import itertools
import logging

from trueseeing.signature.base import Detector, IssueSeverity, IssueConfidence

log = logging.getLogger(__name__)

class ManifestOpenPermissionDetector(Detector):
  option = 'manifest-open-permission'
  
  def do_detect(self):
    # TBD: compare with actual permission needs
    yield from (self.issue(IssueSeverity.INFO, IssueConfidence.CERTAIN, 'AndroidManifest.xml', 'open permissions: %s' % p) for p in self.context.permissions_declared())

class ManifestMissingPermissionDetector(Detector):
  option = 'manifest-missing-permission'
  
  def do_detect(self):
    # TBD: compare with actual permission needs
    pass

class ManifestManipActivity(Detector):
  option = 'manifest-manip-activity'
  
  def do_detect(self):
    yield from (self.issue(IssueSeverity.INFO, IssueConfidence.CERTAIN, 'AndroidManifest.xml', 'manipulatable Activity: %s' % name) for name in set(itertools.chain(
      self.context.parsed_manifest().getroot().xpath('//activity[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
      self.context.parsed_manifest().getroot().xpath('//activity[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
    )))

class ManifestManipBroadcastReceiver(Detector):
  option = 'manifest-manip-broadcastreceiver'
  
  def do_detect(self):
    yield from (self.issue(IssueSeverity.INFO, IssueConfidence.CERTAIN, 'AndroidManifest.xml', 'manipulatable BroadcastReceiver: %s' % name) for name in set(itertools.chain(
      self.context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
      self.context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
    )))
  
