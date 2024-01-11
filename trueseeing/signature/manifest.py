from __future__ import annotations
from typing import TYPE_CHECKING

import itertools
import re
import os

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
      self._raise_issue(Issue(
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
        self._context.parsed_manifest().xpath('//activity[not(@android:permission)]/intent-filter/../@android:name', namespaces=ns),
        self._context.parsed_manifest().xpath('//activity[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=ns),
    )):
      filter_ = [name for name in self._context.parsed_manifest().xpath(f'//activity[@android:name="{name}"]/intent-filter/action/@android:name', namespaces=ns) if not policy.looks_public(name)]
      if not filter_:
        self._raise_issue(Issue(
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
        self._raise_issue(Issue(
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
        self._context.parsed_manifest().xpath('//receiver[not(@android:permission)]/intent-filter/../@android:name', namespaces=ns),
        self._context.parsed_manifest().xpath('//receiver[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=ns),
    )):
      filter_ = [name for name in self._context.parsed_manifest().xpath(f'//receiver[@android:name="{name}"]/intent-filter/action/@android:name', namespaces=ns) if not policy.looks_public(name)]
      if not filter_:
        self._raise_issue(Issue(
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
        self._raise_issue(Issue(
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
        self._context.parsed_manifest().xpath('//provider[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
        self._context.parsed_manifest().xpath('//provider[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
    )):
      filter_ = [name for name in self._context.parsed_manifest().xpath(f'//receiver[@android:name="{name}"]/intent-filter/action/@android:name', namespaces=ns) if not policy.looks_public(name)]
      if not filter_:
        self._raise_issue(Issue(
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
        self._raise_issue(Issue(
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
    manif = self._context.parsed_manifest()
    for e in manif.xpath('//application[not(@android:allowBackup="false")]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
      if min(self._context.get_target_sdk_version(), self._context.get_min_sdk_version()) < 31:
        fbc_exists = (e.attrib.get('{{{ns}}}fullBackupContent'.format(ns='http://schemas.android.com/apk/res/android')) is not None)
        self._raise_issue(Issue(
          detector_id=self.option,
          confidence='certain' if not fbc_exists else 'tentative',
          cvss3_vector=self._cvss,
          summary='manipulatable backups',
          source='AndroidManifest.xml',
          synopsis="Application data can be backed up and restored with the Auto Backup feature.",
          description="Application data can be backed up and restored with the Auto Backup feature, thusly making it subjectible to the backup attack.",
          solution='''\
Review them, and consider controlling backupable data with the Auto Backup feature or completely opt-out from it if necessary.  To control backupable data, associate XML with the following attribute to the <application> tag.

android:fullBackupContent="@xml/fbc"

(Please refer https://developer.android.com/guide/topics/data/autobackup#XMLSyntax for details)

To opt-out, define the following attribute to the <application> tag in the manifest:

android:allowBackup="false"
'''
        ))

class ManifestDebuggable(Detector):
  option = 'manifest-debuggable'
  description = 'Detects enabled debug bits'
  _cvss = 'CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/'

  async def detect(self) -> None:
    if self._context.parsed_manifest().xpath('//application[@android:debuggable="true"]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
      self._raise_issue(Issue(
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

class ManifestCleartextPermitted(Detector):
  option = 'manifest-cleartext-permitted'
  description = 'Detects usesCleartextTraffic flag'
  _cvss = 'CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/'

  async def detect(self) -> None:
    manif = self._context.parsed_manifest()
    api_level = self._context.get_min_sdk_version()
    if api_level < 24:
      if not manif.xpath('//application[@android:usesCleartextTraffic="false"]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
        self._raise('AndroidManifest.xml')
    else:
      for e in manif.xpath('//application', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
        if e.attrib.get('{{{ns}}}networkSecurityConfig'.format(ns='http://schemas.android.com/apk/res/android')) is None:
          if e.attrib.get('{{{ns}}}usesCleartextTraffic'.format(ns='http://schemas.android.com/apk/res/android'), 'true' if api_level < 28 else 'false').lower == 'true':
            self._raise('AndroidManifest.xml')
            break
      for fn, xp in self._context.xml_resources():
        if 'network-security-config' in xp.tag.lower():
          if api_level < 28:
            if not xp.xpath('.//*[@cleartextTrafficPermitted="false"]'):
              self._raise(self._context.source_name_of_disassembled_resource(fn))
          else:
            if xp.xpath('.//*[@cleartextTrafficPermitted="true"]'):
              self._raise(self._context.source_name_of_disassembled_resource(fn))

  def _raise(self, path: str) -> None:
    self._raise_issue(Issue(
      detector_id=self.option,
      confidence='certain',
      cvss3_vector=self._cvss,
      summary='cleartext traffic is permitted',
      source=path,
      synopsis="Application can use cleartext traffic.",
      description="Application can use cleartext traffic.  Cleartext traffic are prone to be intercept and/or manipulated by an active attacker on the wire.",
      solution='''\
Consider migrating all the servers on TLS and disable use of cleartext traffic.  To disable one, associate an Network Security Config disallowing one (API > 24), or discourage ones use in <application> tag as follows (API > 23):

<application android:useCleartextTraffic="false">
'''
    ))
