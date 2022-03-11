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

import asyncio
import re
import math

from pubsub import pub

from trueseeing.core.code.model import InvocationPattern
from trueseeing.core.flow.data import DataFlows
from trueseeing.signature.base import Detector
from trueseeing.core.issue import Issue

if TYPE_CHECKING:
  from typing import Dict, Iterable
  from trueseeing.core.code.model import Op
  from trueseeing.core.store import Store

class CryptoStaticKeyDetector(Detector):
  option = 'crypto-static-keys'
  description = 'Detects cryptographic function usage with static keys'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N/'
  _cvss_nonkey = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

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

  @classmethod
  def _important_args_on_invocation(cls, k: Op) -> Iterable[int]:
    method_name = k.p[1].v
    if re.match('L.*/(SecretKey|(Iv|GCM)Parameter|(PKCS8|X509)EncodedKey)Spec-><init>|L.*/MessageDigest;->update', method_name):
      yield 0
    else:
      yield from range(len(DataFlows.decoded_registers_of_set(k.p[0])))

  async def detect(self) -> None:
    await asyncio.gather(self._do_detect_case1(), self._do_detect_case2())

  async def _do_detect_case1(self) -> None:
    import base64
    import binascii

    def looks_like_real_key(k: str) -> bool:
      # XXX: silly
      return len(k) >= 8 and not any(x in k for x in ('Padding', 'SHA1', 'PBKDF2', 'Hmac', 'emulator'))

    with self._context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-', '^Ljavax?.*/(SecretKey|(Iv|GCM)Parameter|(PKCS8|X509)EncodedKey)Spec|^Ljavax?.*/MessageDigest;->(update|digest)')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        try:
          for nr in self._important_args_on_invocation(cl):
            for found in DataFlows.solved_possible_constant_data_in_invocation(store, cl, nr):
              try:
                decoded = base64.b64decode(found)
                info1 = '"{target_val}" [{target_val_len}] (base64; "{decoded_val}" [{decoded_val_len}])'.format(target_val=found, target_val_len=len(found), decoded_val=binascii.hexlify(decoded).decode('ascii'), decoded_val_len=len(decoded))
              except (ValueError, binascii.Error):
                info1 = f'"{found}" [{len(found)}]'

              if looks_like_real_key(found):
                pub.sendMessage('issue', issue=Issue(
                  detector_id=self.option,
                  cvss3_vector=self._cvss,
                  confidence='firm',
                  summary='insecure cryptography: static keys',
                  info1=info1,
                  info2=store.query().method_call_target_of(cl),
                  source=qn,
                  synopsis='Traces of cryptographic material has been found the application binary.',
                  description='''\
Traces of cryptographic material has been found in the application binary.  If cryptographic material is hardcoded, attackers can extract or replace them.
''',
                  solution='''\
Use a device or installation specific information, or obfuscate them.
'''
                ))
              else:
                pub.sendMessage('issue', issue=Issue(
                  detector_id=self.option,
                  cvss3_vector=self._cvss_nonkey,
                  confidence='tentative',
                  summary='Cryptographic constants detected',
                  info1=info1,
                  info2=store.query().method_call_target_of(cl),
                  source=qn,
                  synopsis='Possible cryptographic constants have been found.',
                  description='''\
Possible cryptographic constants has been found in the application binary.
'''
                ))
        except IndexError:
          pass

  async def _do_detect_case2(self) -> None:
    # XXX: Crude detection
    def should_be_secret(store: Store, k: Op, val: str) -> bool:
      name = store.query().qualname_of(k)
      if name:
        return name.lower() in ['inapp','billing','iab','sku','store','key']
      else:
        return False

    pat = '^MI[IG][0-9A-Za-z+/=-]{32,}AQAB'
    with self._context.store() as store:
      for cl in store.query().consts(InvocationPattern('const-string', pat)):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        val = cl.p[1].v
        pub.sendMessage('issue', issue=Issue(
          detector_id=self.option,
          cvss3_vector=self._cvss,
          confidence={True:'firm', False:'tentative'}[should_be_secret(store, cl, val)], # type: ignore[arg-type]
          summary='insecure cryptography: static keys (2)',
          info1=f'"{val}" [{len(val)}] (X.509)',
          source=qn,
          synopsis='Traces of X.509 certificates has been found the application binary.',
          description='''\
Traces of X.509 certificates has been found in the application binary.  X.509 certificates describe public key materials.  Their notable uses include Google Play in-app billing identity.  If is hardcoded, attackers can extract or replace them.
''',
          solution='''\
Use a device or installation specific information, or obfuscate them.  Especially, do not use the stock implementation of in-app billing logic.
'''
        ))
      for name, val in self._context.string_resources():
        if re.match(pat, val):
          pub.sendMessage('issue', issue=Issue(
            detector_id=self.option,
            cvss3_vector=self._cvss,
            confidence='tentative',
            summary='insecure cryptography: static keys (2)',
            info1=f'"{val}" [{len(val)}] (X.509)',
            source=f'R.string.{name}',
            synopsis='Traces of X.509 certificates has been found the application binary.',
            description='''\
Traces of X.509 certificates has been found in the application binary.  X.509 certificates describe public key materials.  Their notable uses include Google Play in-app billing identity.  If is hardcoded, attackers can extract or replace them.
''',
            solution='''\
Use a device or installation specific information, or obfuscate them.  Especially, do not use the stock implementation of in-app billing logic.
'''
          ))


class CryptoEcbDetector(Detector):
  option = 'crypto-ecb'
  description = 'Detects ECB mode ciphers'
  _cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L/'

  async def detect(self) -> None:
    with self._context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-static', r'Ljavax/crypto/Cipher;->getInstance\(Ljava/lang/String;.*?\)')):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        try:
          target_val = DataFlows.solved_possible_constant_data_in_invocation(store, cl, 0)
          if any((('ECB' in x or '/' not in x) and 'RSA' not in x) for x in target_val):
            pub.sendMessage('issue', issue=Issue(
              detector_id=self.option,
              cvss3_vector=self._cvss,
              confidence='certain',
              summary='insecure cryptography: cipher might be operating in ECB mode',
              info1=','.join(target_val),
              source=qn,
              synopsis='The application might be using ciphers in ECB mode.',
              description='''\
              The application might be using symmetric ciphers in ECB mode.  ECB mode is the most basic operating mode that independently transform data blocks.  Indepent transformation leaks information about distribution in plaintext.
''',
              solution='''\
Use CBC or CTR mode.
'''
            ))
        except (DataFlows.NoSuchValueError):
          pass

class CryptoNonRandomXorDetector(Detector):
  option = 'crypto-xor'
  description = 'Detects Vernum cipher usage with static keys'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/'

  async def detect(self) -> None:
    with self._context.store() as store:
      for cl in store.query().ops_of('xor-int/lit8'):
        qn = store.query().qualname_of(cl)
        if self._context.is_qualname_excluded(qn):
          continue
        target_val = int(cl.p[2].v, 16)
        if (cl.p[0].v == cl.p[1].v) and target_val > 1:
          pub.sendMessage('issue', issue=Issue(
            detector_id=self.option,
            cvss3_vector=self._cvss,
            confidence='firm',
            summary='insecure cryptography: non-random XOR cipher',
            info1=f'0x{target_val:02x}',
            source=store.query().qualname_of(cl)
          ))
