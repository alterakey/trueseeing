from __future__ import annotations
from typing import TYPE_CHECKING

import itertools
import re

from trueseeing.core.model.sig import SignatureMixin

if TYPE_CHECKING:
  from trueseeing.api import Signature, SignatureHelper, SignatureMap

class ManifestOpenPermissionDetector(SignatureMixin):
  _id = 'manifest-open-permission'
  _cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ManifestOpenPermissionDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects declarated permissions')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')

    # TBD: compare with actual permission needs
    for p in context.permissions_declared():
      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cfd='certain',
        cvss=self._cvss,
        title='open permissions',
        info0=p,
        aff0='AndroidManifest.xml',
        summary="Application is requesting one or more permissions.",
        desc="Application is requesting one or more permissions.  Permissions are an important security system of Android.  They control accesses to sensitive information (e.g. GPS, IMEI/IMSI, process stats, accounts, contacts, SMSs) or possibly dangerous/costly operation (e.g. SMSs, internet access, controlling system services, obstructing screens.)  Requesting ones are vital for proper functioning of application, though abusage leads to hurt privacy or device availability.  This issue is just an observation; requesting permissions alone does not constitute an security issue.",
      ))

class ComponentNamePolicy:
  def __init__(self) -> None:
    from importlib.resources import files
    with (files('trueseeing')/'libs'/'tlds.txt').open('r', encoding='utf-8') as f:
      self._re_tlds = re.compile('^(?:{})$'.format('|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#'))), flags=re.IGNORECASE)

  def looks_public(self, name: str) -> bool:
    if '.' in name:
      gtld = name.split('.')[0]
      return (gtld == 'android') or ('.intent.action.' in name) or bool(self._re_tlds.search(gtld))
    else:
      return False

class ManifestManipActivity(SignatureMixin):
  _id = 'manifest-manip-activity'
  description = 'Detects exported Activity'
  _cvss1 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss2 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ManifestManipActivity(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects exported Activity')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    policy = ComponentNamePolicy()
    ns = dict(android='http://schemas.android.com/apk/res/android')

    for name in set(itertools.chain(
        context.parsed_manifest().xpath('//activity[not(@android:permission)]/intent-filter/../@android:name', namespaces=ns),
        context.parsed_manifest().xpath('//activity[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=ns),
    )):
      filter_ = [name for name in context.parsed_manifest().xpath(f'//activity[@android:name="{name}"]/intent-filter/action/@android:name', namespaces=ns) if not policy.looks_public(name)]
      if not filter_:
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain',
          cvss=self._cvss1,
          title='manipulatable Activity',
          info0=name,
          aff0='AndroidManifest.xml',
          summary="Application is exporting one or more activities.",
          desc="Application is exporting one or more activities.  Activities are entrypoints to the application.  Exporting enables them to be invoked from other applications or system.  Unnecessary export increases attack surfaces.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.  This issue is just an observation; exporting activities alone does not constitute an security issue.",
          sol="Review them, and restrict access with application-specific permissions if necessary."
        ))
      else:
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain',
          cvss=self._cvss2,
          title='manipulatable Activity with private action names',
          info0=name,
          info1=', '.join(filter_),
          aff0='AndroidManifest.xml',
          summary="Application is exporting one or more activities using seemingly private action names, suggesting inadvent export.",
          desc="Application is exporting one or more activities using seemingly private action names, suggesting inadvent export.  Activities are entrypoints to the application.  Exporting enables them to be invoked from other applications or system.  Inadvent exporting enables malwares or malicious users to manipulate the application.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.",
          sol="Review them, and restrict access with application-specific permissions if necessary."
        ))

class ManifestManipBroadcastReceiver(SignatureMixin):
  _id = 'manifest-manip-broadcastreceiver'
  _cvss1 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss2 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ManifestManipBroadcastReceiver(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects exported BroadcastReceiver')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    policy = ComponentNamePolicy()
    ns = dict(android='http://schemas.android.com/apk/res/android')

    # FIXME: catch API < 9
    for name in set(itertools.chain(
        context.parsed_manifest().xpath('//receiver[not(@android:permission) and not(@android:exported="false")]/intent-filter/../@android:name', namespaces=ns),
        context.parsed_manifest().xpath('//receiver[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=ns),
    )):
      filter_ = [name for name in context.parsed_manifest().xpath(f'//receiver[@android:name="{name}"]/intent-filter/action/@android:name', namespaces=ns) if not policy.looks_public(name)]
      if not filter_:
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain',
          cvss=self._cvss1,
          title='manipulatable BroadcastReceiver',
          info0=name,
          aff0='AndroidManifest.xml',
          summary="Application is exporting one or more broadcast receivers.",
          desc="Application is exporting one or more broadcast receivers.  Broadcast receivers are system-wide event listeners of the application.  Exporting enables them to be invoked from other applications or system.  Unnecessary export increases attack surfaces.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.  This issue is just an observation; exporting broadcast receivers alone does not constitute an security issue.",
          sol="Review them and restrict access with application-specific permissions if necessary.  Consider the use of LocalBroadcastReceiver for ones that system-wide reachability is not needed."
        ))
      else:
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain',
          cvss=self._cvss2,
          title='manipulatable BroadcastReceiver with private action names',
          info0=name,
          info1=', '.join(filter_),
          aff0='AndroidManifest.xml',
          summary="Application is exporting one or more broadcast receivers using seemingly private action names, suggesting inadvent export.",
          desc="Application is exporting one or more broadcast receivers using seemingly private action names, suggesting inadvent export.  Broadcast receivers are system-wide event listeners of the application.  Exporting enables them to be invoked from other applications or system.  Inadvent exporting enables malwares or malicious users to manipulate the application.  Please note that Android automatically exports ones with IntentFilter defined in the manifest.",
          sol="Review them, and restrict access with application-specific permissions if necessary."
        ))

class ManifestManipContentProvider(SignatureMixin):
  _id = 'manifest-manip-contentprovider'
  _cvss1 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss2 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ManifestManipContentProvider(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects exported ContentProvider')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    policy = ComponentNamePolicy()
    ns = dict(android='http://schemas.android.com/apk/res/android')

    for name in set(itertools.chain(
        context.parsed_manifest().xpath('//provider[not(@android:permission)]/intent-filter/../@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
        context.parsed_manifest().xpath('//provider[not(@android:permission) and (@android:exported="true")]/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android')),
    )):
      filter_ = [name for name in context.parsed_manifest().xpath(f'//receiver[@android:name="{name}"]/intent-filter/action/@android:name', namespaces=ns) if not policy.looks_public(name)]
      if not filter_:
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain',
          cvss=self._cvss1,
          title='manipulatable ContentProvider',
          info0=name,
          aff0='AndroidManifest.xml',
          summary="Application is exporting one or more content providers.",
          desc="Application is exporting one or more content providers.  Content providers defines REST/RDBMS-like IPC mechanism for the application.  Exporting enables them to be invoked from other applications or system.  Unnecessary export increases attack surfaces.  Please note that Android automatically exports them (API 8 or ealier) or ones with IntentFilter defined in the manifest (API level 9 or later).  This issue is just an observation; exporting content providers alone does not constitute an security issue.",
          sol='''\
  Review them and explicitly unexport or restrict access with application-specific permissions if necessary.  To explicitly unexporting an content provider, define the following attribute to the <provider> tag in the manifest:

  android:export="false"
  '''
        ))
      else:
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain',
          cvss=self._cvss2,
          title='manipulatable ContentProvider with private action names',
          info0=name,
          info1=', '.join(filter_),
          aff0='AndroidManifest.xml',
          summary="Application is exporting one or more content providers using seemingly private action names, suggesting inadvent export.",
          desc="Application is exporting one or more content providers using seemingly private action names, suggesting inadvent export.  Content providers defines REST/RDBMS-like IPC mechanism for the application.  Exporting enables them to be invoked from other applications or system.  Inadvent exporting enables malwares or malicious users to manipulate the application.  Please note that Android automatically exports them (API 8 or ealier) or ones with IntentFilter defined in the manifest (API level 9 or later).",
          sol='''\
  Review them and explicitly unexport or restrict access with application-specific permissions if necessary.  To explicitly unexporting an content provider, define the following attribute to the <provider> tag in the manifest:

  android:export="false"
  '''
        ))

class ManifestManipBackup(SignatureMixin):
  _id = 'manifest-manip-backup'
  _cvss = 'CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ManifestManipBackup(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects enabled backup bit')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    manif = context.parsed_manifest()
    for e in manif.xpath('//application[not(@android:allowBackup="false")]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
      if min(context.get_target_sdk_version(), context.get_min_sdk_version()) < 31:
        fbc_exists = (e.attrib.get('{{{ns}}}fullBackupContent'.format(ns='http://schemas.android.com/apk/res/android')) is not None)
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cfd='certain' if not fbc_exists else 'tentative',
          cvss=self._cvss,
          title='manipulatable backups',
          aff0='AndroidManifest.xml',
          summary="Application data can be backed up and restored with the Auto Backup feature.",
          desc="Application data can be backed up and restored with the Auto Backup feature, thusly making it subjectible to the backup attack.",
          sol='''\
Review them, and consider controlling backupable data with the Auto Backup feature or completely opt-out from it if necessary.  To control backupable data, associate XML with the following attribute to the <application> tag.

android:fullBackupContent="@xml/fbc"

(Please refer https://developer.android.com/guide/topics/data/autobackup#XMLSyntax for details)

To opt-out, define the following attribute to the <application> tag in the manifest:

android:allowBackup="false"
'''
        ))

class ManifestDebuggable(SignatureMixin):
  _id = 'manifest-debuggable'
  _cvss = 'CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ManifestDebuggable(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects enabled debug bits')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    if context.parsed_manifest().xpath('//application[@android:debuggable="true"]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cfd='certain',
        cvss=self._cvss,
        title='app is debuggable',
        aff0='AndroidManifest.xml',
        summary="Application can be debugged.",
        desc="Application can be debugged (the debuggable bit is set.)  Debugging it gives attackers complete control of its process memory and control flow.",
        sol='''\
Disable the debuggable bit.  To disable it, define the following attribute to the <application> tag in the manifest:

android:debuggable="false"
'''
      ))

class ManifestCleartextPermitted(SignatureMixin):
  _id = 'manifest-cleartext-permitted'
  _cvss = 'CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return ManifestCleartextPermitted(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id:dict(e=self.detect, d='Detects usesCleartextTraffic flag')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    manif = context.parsed_manifest()
    api_level = context.get_min_sdk_version()
    if api_level < 24:
      if not manif.xpath('//application[@android:usesCleartextTraffic="false"]', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
        self._raise('AndroidManifest.xml')
    else:
      for e in manif.xpath('//application', namespaces=dict(android='http://schemas.android.com/apk/res/android')):
        if e.attrib.get('{{{ns}}}networkSecurityConfig'.format(ns='http://schemas.android.com/apk/res/android')) is None:
          if e.attrib.get('{{{ns}}}usesCleartextTraffic'.format(ns='http://schemas.android.com/apk/res/android'), 'true' if api_level < 28 else 'false').lower == 'true':
            self._raise('AndroidManifest.xml')
            break
      for fn, xp in context.xml_resources():
        if 'network-security-config' in xp.tag.lower():
          if api_level < 28:
            if not xp.xpath('.//*[@cleartextTrafficPermitted="false"]'):
              self._raise(context.source_name_of_disassembled_resource(fn))
          else:
            if xp.xpath('.//*[@cleartextTrafficPermitted="true"]'):
              self._raise(context.source_name_of_disassembled_resource(fn))

  def _raise(self, path: str) -> None:
    self._helper.raise_issue(self._helper.build_issue(
      sigid=self._id,
      cfd='certain',
      cvss=self._cvss,
      title='cleartext traffic is permitted',
      aff0=path,
      summary="Application can use cleartext traffic.",
      desc="Application can use cleartext traffic.  Cleartext traffic are prone to be intercept and/or manipulated by an active attacker on the wire.",
      sol='''\
Consider migrating all the servers on TLS and disable use of cleartext traffic.  To disable one, associate an Network Security Config disallowing one (API > 24), or discourage ones use in <application> tag as follows (API > 23):

<application android:useCleartextTraffic="false">
'''
    ))
