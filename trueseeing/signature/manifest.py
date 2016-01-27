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

from trueseeing.context import warning_on
from trueseeing.signature.base import Detector

log = logging.getLogger(__name__)

class ManifestOpenPermissionDetector(Detector):
  def detect(self):
    # TBD: compare with actual permission needs
    return [warning_on(name='AndroidManifest.xml', row=1, col=0, desc='open permissions: %s' % p, opt='-Wmanifest-open-permission') for p in self.context.permissions_declared()]

class ManifestMissingPermissionDetector(Detector):
  def detect(self):
    # TBD: compare with actual permission needs
    return []

class ManifestManipActivity(Detector):
  def detect(self):
    return [warning_on(name='AndroidManifest.xml', row=1, col=0, desc='manipulatable Activity: %s' % name, opt='-Wmanifest-manip-activity') for name in set(itertools.chain(
      self.context.parsed_manifest().getroot().xpath('//activity[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
      self.context.parsed_manifest().getroot().xpath('//activity[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
    ))]

class ManifestManipBroadcastReceiver(Detector):
  def detect(self):
    return [warning_on(name='AndroidManifest.xml', row=1, col=0, desc='manipulatable BroadcastReceiver: %s' % name, opt='-Wmanifest-manip-broadcastreceiver') for name in set(itertools.chain(
      self.context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
      self.context.parsed_manifest().getroot().xpath('//receiver[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
    ))]
  
  
def check_manifest_open_permission(context):
  return ManifestOpenPermissionDetector(context).detect()

def check_manifest_missing_permission(context):
  return ManifestMissingPermissionDetector(context).detect()

def check_manifest_manip_activity(context):
  return ManifestManipActivity(context).detect()

def check_manifest_manip_broadcastreceiver(context):
  return ManifestManipBroadcastReceiver(context).detect()
