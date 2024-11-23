from __future__ import annotations
from typing import TYPE_CHECKING

import math
import re
from trueseeing.api import Signature
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Dict, Optional, Mapping, Any, AnyStr, Set
  from trueseeing.api import SignatureMap, SignatureHelper, ConfigMap
  from trueseeing.core.ios.model import Call
  from trueseeing.core.ios.db import IPAQuery
  from trueseeing.core.ios.context import IPAContext

class IOSDetector(Signature):
  _cvss_info = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def __init__(self, helper: SignatureHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return IOSDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {
      'ios-nat-api':dict(e=self._detect_api, d='[iOS] Detects API call'),
      'ios-nat-urls':dict(e=self._detect_url, d='[iOS] Detects URL etc.'),
      'ios-detect-dyncode':dict(e=self._detect_dyncode, d='[iOS] Detects dynamic code exec attempt'),
      'ios-detect-syscall':dict(e=self._detect_inconsistent_syscall, d='[iOS] Detects syscalls looks inconsistent'),
      'ios-detect-reflection':dict(e=self._detect_reflection, d='[iOS] Detects possible reflections'),
      'ios-detect-jb':dict(e=self._detect_jb, d='[iOS] Detects possible JB probes'),
      'ios-detect-debug':dict(e=self._detect_debug, d='[iOS] Detects possible debug probes'),
      'ios-detect-privacy':dict(e=self._detect_privacy, d='[iOS] Detects privacy concerns'),
      'ios-detect-obfus':dict(e=self._detect_obfuscation, d='[iOS] Detects obfuscated functions'),
      'ios-detect-assert':dict(e=self._detect_assert, d='[iOS] Detects assertions'),
      'ios-detect-logging':dict(e=self._detect_log, d='[iOS] Detects log'),
      'ios-detect-lib-needed':dict(e=self._detect_needed_libs, d='[iOS] Detects needed libraries'),
      'ios-detect-motion':dict(e=self._detect_motion, d='[iOS] Detects use of motion/gyro etc.'),
      'ios-detect-urlscheme':dict(e=self._detect_urlscheme, d='[iOS] Detects recognized URL schemes'),
      'ios-detect-ats':dict(e=self._detect_ats, d='[iOS] Detects ATS status'),
      'ios-detect-permission':dict(e=self._detect_permission, d='[iOS] Detects protected resource accesses'),
      'ios-detect-req':dict(e=self._detect_device_req, d='[iOS] Detected device requirements'),
      'ios-detect-device':dict(e=self._detect_device_info, d='[iOS] Detects device info probes'),
      'ios-detect-ents':dict(e=self._detect_entitlements, d='[iOS] Detects entitlements'),
      'ios-detect-copyrights':dict(e=self._detect_copyrights, d='[iOS] Detects copyright banners'),
      'ios-detect-crypto-xor':dict(e=self._detect_crypto_xor, d='[iOS] Detects Vernum cipher usage with static keys'),
      'ios-detect-libs':dict(e=self._detect_libs, d='[iOS] Detects statically-linked libs'),
    }

  def get_configs(self) -> ConfigMap:
    return dict()

  def _get_ipa_context(self) -> IPAContext:
    return self._helper.get_context().require_type('ipa') # type:ignore[return-value]

  def _format_aff0(self, c: Call) -> str:
    return self._format_aff0_manual(c['path'], c['sect'], c['offs'])

  def _format_aff0_match(self, n: str, m: re.Match[AnyStr]) -> str:
    return self._format_aff0_manual(n, '', m.start())

  def _format_aff0_manual(self, n: str, s: str, o: int) -> str:
    return '{} ({}+{:08x})'.format(n, s, o)

  async def _detect_api(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      from trueseeing.core.ios.swift import SwiftDemangler
      async with SwiftDemangler.get(simplify=True).scoped() as dem:
        for c in q.calls():
          priv, target, swift = c['priv'], c['target'], c['swift']
          if swift:
            target = await dem.resolve(target)
          self._helper.raise_issue(self._helper.build_issue(
            sigid='ios-nat-api',
            cvss=self._cvss_info,
            title='detected {} call'.format('private' if priv else 'API'),
            info0=target,
            aff0=self._format_aff0(c),
          ))

  async def _detect_url(self) -> None:
    from trueseeing.core.analyze import analyze_url_in
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for d in analyze_url_in(q.file_enum('disasm/%', neg=True)):
        tentative = False
        if '...' in d['v']:
          ui.warn('truncated value found; disassemble again with wider fields', onetime=True)
          tentative = True
        self._helper.raise_issue(self._helper.build_issue(
          sigid='ios-nat-urls',
          cvss=self._cvss_info,
          title='detected {}'.format(d['typ']),
          cfd='tentative' if tentative else 'firm',
          info0=d['v'],
          aff0=d['fn'],
        ))

  async def _detect_dyncode(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls():
        if '_text' in c['sect']:
          if not c['priv'] and '_dlopen' in c['target']:
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-dynload',
              cvss=self._cvss_info,
              title='dynamically loading code',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

          if re.search(r'VmStack|vm_stack|vm_err|StackPool|stack_pool|FunctionCopy|push_[if]64\(', c['target']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-dynload',
              cvss=self._cvss_info,
              title='detected VM-like impl',
              cfd='tentative',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

  async def _detect_inconsistent_syscall(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls(api=True):
        if '_text' in c['sect']:
          if any((x in c['target']) for x in ['_fork', '_vfork', '_syscall']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-syscall',
              cvss=self._cvss_info,
              title='inconsistent syscall',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

  async def _detect_reflection(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls(api=True):
        if '_text' in c['sect']:
          if any((x in c['target']) for x in ['NSInvocation', '_NSClassFromString']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-reflection',
              cvss=self._cvss_info,
              title='use of reflection',
              cfd='tentative',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))
          elif '_class_add' in c['target']:
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-reflection',
              cvss=self._cvss_info,
              title='monkeypatching of class',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

  async def _detect_jb(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls(api=True):
        if '_text' in c['sect']:
          if any((x in c['target']) for x in ['Jail', 'jailb']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-jb',
              cvss=self._cvss_info,
              title='possible JB probe',
              cfd='tentative',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

  async def _detect_debug(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls(api=True):
        if '_text' in c['sect']:
          if any((x in c['target']) for x in ['Debuggi', 'debuggi']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-debug',
              cvss=self._cvss_info,
              title='possible debug probe',
              cfd='tentative',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

  async def _detect_privacy(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls():
        mentioned = False
        if '_text' in c['sect']:
          if not c['priv']:
            if ' uniqueDeviceIdentifer]' in c['target']:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('UDID'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            if ' uniqueGlobalDeviceIdentifer]' in c['target']:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('UGDID'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif ' identifierForVe' in c['target']:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('IDFV'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif ' resettable' in c['target']:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('resettable device id'),
                cfd='tentative',
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif re.search(r' currentCarrier| carrierName\]', c['target']):
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('carrier'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif ' mobileCountryCode' in c['target']:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('MCC'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif ' mobileNetworkCode' in c['target']:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('MNC'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif ' freeDiskspace' in c['target']:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('device info (diskspace)'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif ' currencyCode' in c['target']:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('user preference (currency)'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            if re.search(r'\[GMSCoordinateBounds (isValid|(north|south)(West|East))\]|_CLLocation', c['target']):
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format('location'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif re.search(r'pasteboard.*?change', c['target'], flags=re.IGNORECASE):
              mentioned = True
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: watching pasteboard',
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif re.search(r'(data|value)forpasteboard', c['target'], flags=re.IGNORECASE):
              mentioned = True
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: reading pasteboard',
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
            elif re.search(r'setdata:.*?forpasteboardtype', c['target'], flags=re.IGNORECASE):
              mentioned = True
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: writing pasteboard',
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))

          if 'Pasteboard' in c['target']:
            if not mentioned:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: referring pasteboard',
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))
          elif '[ABKDevice ' in c['target']:
            m = re.search(r'\[ABKDevice (.*?)\]', c['target'])
            parts = m.group(1) if m else 'unknown'
            if not parts.startswith('set'):
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-privacy',
                cvss=self._cvss_info,
                title='privacy concern: getting {}'.format(f'device info ({parts} [ABKDevice])'),
                info0=c['target'],
                aff0=self._format_aff0(c),
              ))

  async def _detect_obfuscation(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls():
        if '_text' in c['sect']:
          m = re.search(r' _[A-Z]+([a-z]{3,5}_[a-z]{2,4}(?:_[a-z]{2,6})?)\(', c['target'])
          if m:
            ent = self._entropy_of(m.group(1))
            if ent < 2.8 and not re.search(r' _BDP(mpi|rsa)', c['target']):
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-obfus',
                cvss=self._cvss_info,
                title='possible obfuscated function',
                cfd='tentative',
                info0=c['target'],
                info1=f'{ent:.04f}',
                aff0=self._format_aff0(c),
              ))

  async def _detect_assert(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls(api=True):
        if '_text' in c['sect']:
          if '_assertionFailure_' in c['target']:
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-assert',
              cvss=self._cvss_info,
              title='possible live assertion check',
              cfd='tentative',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

  async def _detect_log(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls(api=True):
        if '_text' in c['sect']:
          if '_NSLog' in c['target']:
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-logging',
              cvss=self._cvss_info,
              title='detected logging',
              cfd='tentative',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

  async def _detect_needed_libs(self) -> None:
    from trueseeing.core.ios.analyze import analyze_lib_needs_in
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for d in analyze_lib_needs_in(q.file_enum('^disasm/|/_CodeSignature/', neg=True, regex=True)):
        self._helper.raise_issue(self._helper.build_issue(
          sigid='ios-detect-lib-needed',
          cvss=self._cvss_info,
          title='detected library reference',
          cfd='firm',
          info0=d['v'],
          aff0=d['fn'],
        ))

  async def _detect_motion(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls(api=True):
        if '_text' in c['sect']:
          if re.search(r'startGyro| (gyroUpdateInterval|rotationRate)\]', c['target']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-motion',
              cvss=self._cvss_info,
              title='watching gyroscope',
              cfd='firm',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))
          if re.search(r'startAccelero| (accelerometerUpdateInterval|(a|userA)cceleration)\]', c['target']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-motion',
              cvss=self._cvss_info,
              title='watching accelerometer',
              cfd='tentative',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))
          if re.search(r'startDeviceMotion| (deviceMotionUpdateInterval|gravity)\]', c['target']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-motion',
              cvss=self._cvss_info,
              title='watching motion',
              cfd='tentative',
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

  async def _detect_urlscheme(self) -> None:
    q: IPAQuery
    from plistlib import loads
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for n, b in q.file_enum('Payload/.*?.app/Info.plist', regex=True):
        dom = loads(b)
        if 'LSApplicationQueriesSchemes' in dom:
          v = dom['LSApplicationQueriesSchemes']
          for scheme in v:
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-urlscheme',
              cvss=self._cvss_info,
              title='probing URL scheme',
              cfd='firm',
              info0=scheme,
              aff0=n,
            ))
        if 'CFBundleURLTypes' in dom:
          v = dom['CFBundleURLTypes']
          for d in v:
            for scheme in d.get('CFBundleURLSchemes', []):
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-urlscheme',
                cvss=self._cvss_info,
                title='handling URL scheme',
                cfd='firm',
                info0=scheme,
                info1=d.get('CFBundleURLName', '(unknown name)'),
                info2=d.get('CFBundleTypeRole', '(unknown role)'),
                aff0=n,
              ))

  async def _detect_ats(self) -> None:
    q: IPAQuery
    from plistlib import loads
    context = self._get_ipa_context()
    cvss0 = 'CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/'
    cvss1 = 'CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/'
    with context.store().query().scoped() as q:
      for n, b in q.file_enum('Payload/.*?.app/Info.plist', regex=True):
        dom = loads(b)
        if 'NSAppTransportSecurity' in dom:
          v = dom['NSAppTransportSecurity']
          if v.get('NSAllowsArbitraryLoads'):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-ats',
              cvss=cvss0,
              title='disabing ATS',
              cfd='firm',
              aff0=n,
            ))
          if v.get('NSAllowsArbitraryLoadsInWebContent'):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-ats',
              cvss=cvss1,
              title='disabling ATS for web content',
              cfd='firm',
              aff0=n,
            ))
          if v.get('NSAllowsArbitraryLoadsForMedia'):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-ats',
              cvss=cvss1,
              title='disabling ATS for media',
              cfd='firm',
              aff0=n,
            ))
          if v.get('NSAllowsLocalNetworking'):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-ats',
              cvss=cvss1,
              title='use of local networking',
              cfd='firm',
              aff0=n,
            ))
          if v.get('NSAllowsLocalNetworking'):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-ats',
              cvss=cvss1,
              title='use of local networking',
              cfd='firm',
              aff0=n,
            ))
          if v.get('NSExceptionDomains'):
            for name, desc in v['NSExceptionDomains'].items():
              include_subdomains = desc.get('NSIncludeSubdomains', False)
              if desc.get('NSExceptionAllowsInsecureHTTPLoads'):
                self._helper.raise_issue(self._helper.build_issue(
                  sigid='ios-detect-ats',
                  cvss=cvss1,
                  title='partially disabing ATS',
                  cfd='firm',
                  info0='{}{}'.format('*.' if include_subdomains else '', name),
                  aff0=n,
                ))
              else:
                self._helper.raise_issue(self._helper.build_issue(
                  sigid='ios-detect-ats',
                  cvss=self._cvss_info,
                  title='partially enabling ATS',
                  cfd='firm',
                  info0='{}{}'.format('*.' if include_subdomains else '', name),
                  aff0=n,
                ))
              if desc.get('NSExceptionMinimumTLSVersion', 'TLSv1.3').lower() != 'tlsv1.3':
                self._helper.raise_issue(self._helper.build_issue(
                  sigid='ios-detect-ats',
                  cvss=cvss1,
                  title='partial use of lower TLS version',
                  cfd='firm',
                  info0='{}{}'.format('*.' if include_subdomains else '', name),
                  info1=desc['NSExceptionMinimumTLSVersion'],
                  aff0=n,
                ))
              if not desc.get('NSExceptionRequiresForwardSecrecy'):
                self._helper.raise_issue(self._helper.build_issue(
                  sigid='ios-detect-ats',
                  cvss=cvss0,
                  title='partially allowing use of non-PFS ciphers',
                  cfd='firm',
                  info0='{}{}'.format('*.' if include_subdomains else '', name),
                  aff0=n,
                ))
              if not desc.get('NSRequiresCertificateTransparency'):
                self._helper.raise_issue(self._helper.build_issue(
                  sigid='ios-detect-ats',
                  cvss=self._cvss_info,
                  title='attempts to partially disable CT',
                  cfd='firm',
                  info0='{}{}'.format('*.' if include_subdomains else '', name),
                  aff0=n,
                ))
          if v.get('NSPinnedDomains'):
            from base64 import b64decode
            from binascii import hexlify
            for name, desc in v['NSPinnedDomains'].items():
              include_subdomains = desc.get('NSIncludeSubdomains', False)
              if desc.get('NSPinnedLeafIdentities'):
                idents = desc['NSPinnedLeafIdentities']
                for ident in idents:
                  for algo, h in ident.items():
                    m = re.fullmatch(r'SPKI-(.*?)-BASE64', algo)
                    if m:
                      algo = m.group(1)
                      h = hexlify(b64decode(h)).decode()
                    self._helper.raise_issue(self._helper.build_issue(
                      sigid='ios-detect-ats',
                      cvss=self._cvss_info,
                      title='detected TLS certificate pinning',
                      cfd='firm',
                      info0='{}{}'.format('*.' if include_subdomains else '', name),
                      info1='{} ({})'.format(h, algo),
                      aff0=n,
                    ))

  async def _detect_permission(self) -> None:
    q: IPAQuery
    from plistlib import loads
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for n, b in q.file_enum('Payload/.*?.app/Info.plist', regex=True):
        dom = loads(b)

        m = dict(
          NSBluetoothAlwaysUsageDescription='persistent Bluetooth access',
          NSBluetoothPeripheralUsageDescription='Bluetooth peripheral access',
          NSCalendarsFullAccessUsageDescription='calendar read/write access',
          NSCalendarsWriteOnlyAccessUsageDescription='calendar write access',
          NSRemindersFullAccessUsageDescription='reminder read/write access',
          NSCameraUsageDescription='camera access',
          NSMicrophoneUsageDescription='microphone access',
          NSContactsUsageDescription='contact read access',
          NSFaceIDUsageDescription='FaceID access',
          NSGKFriendListUsageDescription='GameCenter friend list access',
          NSHealthClinicalHealthRecordsShareUsageDescription='clinical record read access',
          NSHealthShareUsageDescription='HealthKit sample read access',
          NSHealthUpdateUsageDescription='HealthKit sample write access',
          NSHomeKitUsageDescription='HomeKit config read access',
          NSLocationAlwaysAndWhenInUseUsageDescription='persistent location access',
          NSLocationUsageDescription='location access',
          NSLocationWhenInUseUsageDescription='foreground location access',
          NSLocationTemporaryUsageDescriptionDictionary='temporary location access',
          NSLocationAlwaysUsageDescription='persistent location access',
          NSAppleMusicUsageDescription='media library access',
          NSMotionUsageDescription='motion read access',
          NSFallDetectionUsageDescription='fall detection read access',
          NSLocalNetworkUsageDescription='local network access',
          NSNearbyInteractionUsageDescription='nearby device interaction access',
          NSNearbyInteractionAllowOnceUsageDescription='temporary nearby device interaction access',
          NFCReaderUsageDescription='NFC read access',
          NSPhotoLibraryAddUsageDescription='photo library append access',
          NSPhotoLibraryUsageDescription='photo library read/write access',
          NSUserTrackingUsageDescription='device tracking access',
          NSSensorKitUsageDescription='sensor read access',
          NSSiriUsageDescription='Siri integration access',
          NSSpeechRecognitionUsageDescription='speech recognition access',
          NSVideoSubscriberAccountUsageDescription='TV provider account access',
          NSWorldSensingUsageDescription='world-sensing data access',
          NSHandsTrackingUsageDescription='hand tracking data access',
          NSIdentityUsageDescription='Wallet identity access',
          NSCalendarsUsageDescription='calendar read/write access',
          NSRemindersUsageDescription='reminder read/write access',
        )

        for k, res in m.items():
          v = dom.get(k)
          if v:
            if isinstance(v, dict):
              for vk, vv in v.items():
                self._helper.raise_issue(self._helper.build_issue(
                  sigid='ios-detect-permission',
                  cvss=self._cvss_info,
                  title=f'declaring {res}',
                  cfd='firm',
                  info0='{} ({})'.format(vv, vk),
                  aff0=n,
                ))
            else:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-permission',
                cvss=self._cvss_info,
                title=f'declaring {res}',
                cfd='firm',
                info0=v,
                aff0=n,
              ))

  async def _detect_device_req(self) -> None:
    q: IPAQuery
    from plistlib import loads
    context = self._get_ipa_context()
    cvss0 = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/'
    with context.store().query().scoped() as q:
      for n, b in q.file_enum('Payload/.*?.app/Info.plist', regex=True):
        dom = loads(b)
        d = dom.get('UISupportedDevices')
        if d:
          for k in d:
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-device',
              cvss=self._cvss_info,
              title='detected required device model',
              cfd='firm',
              info0=k,
              aff0=n,
            ))
        d = dom.get('UIDeviceFamily')
        if d:
          for k in d:
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-device',
              cvss=self._cvss_info,
              title='detected targetted device family',
              cfd='firm',
              info0={1:'iPhone/iPod Touch', 2:'iPad/Mac Catalyst (for iPad)', 3:'Apple TV', 4:'Apple Watch', 6:'Mac Catalyst (for Mac)', 7:'Apple Vision'}.get(k, '(unknown)'),
              aff0=n,
            ))
        d = dom.get('LSRequiresIPhoneOS')
        if not d:
          self._helper.raise_issue(self._helper.build_issue(
            sigid='ios-detect-device',
            cvss=cvss0,
            title='insufficient device integrity check: iOS is not required',
            cfd='tentative',
            aff0=n,
          ))
        d = dom.get('MinimumOSVersion')
        if d:
          self._helper.raise_issue(self._helper.build_issue(
            sigid='ios-detect-device',
            cvss=self._cvss_info,
            title='detected minimum OS version',
            cfd='firm',
            info0=d,
            aff0=n,
          ))
        d = dom.get('UIRequiredDeviceCapabilities')
        if d:
          for k in ['arm64', 'armv7']:
            if k in d:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-device',
                cvss=self._cvss_info,
                title='detected required architecture',
                cfd='firm',
                info0=k,
                aff0=n,
              ))

  async def _detect_device_info(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for c in q.calls():
        if '_text' in c['sect']:
          if re.search(r' osName]', c['target']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-device',
              cvss=self._cvss_info,
              title='getting device {}'.format('OS name'),
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))
          if re.search(r' osVersion\]|OSVersion', c['target']) and not re.search(r'support|minim|atleast', c['target']):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-device',
              cvss=self._cvss_info,
              title='getting device {}'.format('OS version'),
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))
          if re.search(r' (device)?model\]', c['target'], re.IGNORECASE):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-device',
              cvss=self._cvss_info,
              title='getting device {}'.format('model number'),
              info0=c['target'],
              aff0=self._format_aff0(c),
              cfd='firm' if 'device' in c['target'] else 'tentative',
            ))
          if re.search(r'sysctl', c['target'], re.IGNORECASE):
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-device',
              cvss=self._cvss_info,
              title='getting device {}'.format('kernel tunables'),
              info0=c['target'],
              aff0=self._format_aff0(c),
            ))

  async def _detect_entitlements(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for n, b in q.file_enum(r'Payload/(.*?).app/\1', regex=True):
        ents = self._get_entitlements(b)
        if ents:
          for k, v in ents.items():
            self._helper.raise_issue(self._helper.build_issue(
              sigid='ios-detect-ents',
              cvss=self._cvss_info,
              title='detected entitlement',
              cfd='firm',
              info0=k,
              info1=repr(v),
              aff0=n,
            ))

  async def _detect_copyrights(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for n, b in q.file_enum('Payload/%'):
        for m in re.finditer(rb'(?:Copyright )?\(C\) [\x20-\xff]+', b, re.IGNORECASE):
          banner = m.group(0)
          if any((x in banner) for x in [b'You must retain', b'allow any third party to access', b' -> ']):
            continue
          m0 = re.match(rb'(.*)(?:<[a-z]+ ?/>|</[a-z]+>|\*/)$', banner)
          if m0:
            banner = m0.group(1)
          self._helper.raise_issue(self._helper.build_issue(
            sigid='ios-detect-ents',
            cvss=self._cvss_info,
            title='detected copyright banner',
            cfd='firm',
            info0=banner.decode('latin1'),
            aff0=self._format_aff0_match(n, m),
          ))

  async def _detect_crypto_xor(self) -> None:
    from trueseeing.core.ios.analyze import get_origin
    q: IPAQuery
    context = self._get_ipa_context()
    with context.store().query().scoped() as q:
      for n, b in q.file_enum('disasm/%.s'):
        for m in re.finditer(rb'^.*? eor .*#(0x[0-9a-f]+)', b, re.MULTILINE):
          mask = m.group(1)
          if re.search(rb'^0x[124837cf]$|^0x[12483cf]0$|^0x[137bde2c]f$|00$|ff$|ffff|0000', mask):
            continue
          o = get_origin(n, m.group(0))
          self._helper.raise_issue(self._helper.build_issue(
            sigid='ios-detect-crypto-xor',
            cvss=self._cvss_info,
            title='detected non-random XOR cipher',
            cfd='tentative',
            info0='0x{:02x}'.format(int(mask, 16)),
            aff0=self._format_aff0_manual(o['fn'], o['sect'], o['offs']),
          ))

  async def _detect_libs(self) -> None:
    q: IPAQuery
    context = self._get_ipa_context()
    seen: Dict[str, Dict[str, Set[str]]] = dict(det=dict(), ref=dict())
    with context.store().query().scoped() as q:
      for c in q.calls():
        if '_text' in c['sect']:
          m = re.search(r'[\[ ]([A-Z]{2,})[A-Z][a-z]', c['target'])
          if m:
            prefix = m.group(1)
            path = c['path']
            ref = not c['priv']
            sk = 'ref' if ref else 'det'
            try:
              lseen = seen[sk][path]
            except KeyError:
              lseen = set()
              seen[sk][path] = lseen
            if prefix not in lseen:
              self._helper.raise_issue(self._helper.build_issue(
                sigid='ios-detect-libs',
                cvss=self._cvss_info,
                title='detected library{}'.format(' ref' if ref else ''),
                info0=prefix,
                aff0=self._format_aff0(c),
              ))
              lseen.add(prefix)

  def _get_entitlements(self, app: bytes) -> Optional[Mapping[str, Any]]:
    from plistlib import loads
    m = re.search(rb'<\?xml [^\x00-\x08\x0b-\x1f\x80-\xff]+?<plist [^\x00-\x08\x0b-\x1f\x80-\xff]+?application-identifier[^\x00-\x08\x0b-\x1f\x80-\xff]+?</plist>', app, re.DOTALL)
    if m:
      return loads(m.group(0))  # type:ignore[no-any-return]
    else:
      return None

  @classmethod
  def _entropy_of(cls, string: str) -> float:
    o = 0.0
    m: Dict[str, int] = dict()
    for c in string:
      m[c] = m.get(c, 0) + 1
    for cnt in m.values():
      freq = float(cnt) / len(string)
      o -= freq * (math.log(freq) / math.log(2))
    return o

  @classmethod
  def _assumed_randomness_of(cls, string: str) -> float:
    try:
      return cls._entropy_of(string) / float(math.log(len(string)) / math.log(2))
    except ValueError:
      return 0
