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
# * Cryptography: Insecure cryptography: Static keys
# * Cryptography: Insecure cryptography: ECB
# * Cryptography: Insecure cryptography: CBC with fixed key/IV (WIP)
# * Cryptography: Insecure cryptography: CFB/OFB with fixed key/IV (WIP)
# * Cryptography: Insecure cryptography: CTR with same counter and key (WIP)
# * Cryptography: Insecure cryptography: non-random XOR cipher
# * Cryptography: Insecure cryptography: implicit trust on non-authenticated data (WIP)

import binascii
import functools
import itertools
import lxml.etree as ET
import shutil
import re
import math
import base64
import os
import logging

from trueseeing.flow.code import InvocationPattern
from trueseeing.flow.data import DataFlows
from trueseeing.signature.base import Detector
from trueseeing.issue import IssueConfidence, Issue

log = logging.getLogger(__name__)

class CryptoStaticKeyDetector(Detector):
  option = 'crypto-static-keys'
  description = 'Detects cryptographic function usage with static keys'
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/'
  cvss_nonkey = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'

  def entropy_of(self, string):
    o = 0.0
    m = dict()
    for c in string:
      m[c] = m.get(c, 0) + 1
    for cnt in m.values():
      freq = float(cnt) / len(string)
      o -= freq * (math.log(freq) / math.log(2))
    return o

  def assumed_randomness_of(self, string):
    try:
      return self.entropy_of(string) / float(math.log(len(string)) / math.log(2))
    except ValueError:
      return 0

  def important_args_on_invocation(self, k):
    method_name = k.p[1].v
    if re.match('L.*/(SecretKey|(Iv|GCM)Parameter|(PKCS8|X509)EncodedKey)Spec-><init>|L.*/MessageDigest;->update', method_name):
      yield 0
    else:
      yield from range(len(DataFlows.decoded_registers_of(k.p[0])))

  def do_detect(self):
    yield from itertools.chain(self.do_detect_case1(), self.do_detect_case2())

  def do_detect_case1(self):
    def looks_like_real_key(k):
      # XXX: silly
      return len(k) >= 8 and not any(x in k for x in ('Padding', 'SHA1', 'PBKDF2', 'Hmac', 'emulator'))

    with self.context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-', '^Ljavax?.*/(SecretKey|(Iv|GCM)Parameter|(PKCS8|X509)EncodedKey)Spec|^Ljavax?.*/MessageDigest;->(update|digest)')):
        try:
          for nr in self.important_args_on_invocation(cl):
            for found in DataFlows.solved_possible_constant_data_in_invocation(store, cl, nr):
              try:
                decoded = base64.b64decode(found)
                info1 = '"%(target_val)s" [%(target_val_len)d] (base64; "%(decoded_val)s" [%(decoded_val_len)d])' % dict(target_val=found, target_val_len=len(found), decoded_val=binascii.hexlify(decoded).decode('ascii'), decoded_val_len=len(decoded))
              except (ValueError, binascii.Error):
                info1 = '"%(target_val)s" [%(target_val_len)d]' % dict(target_val=found, target_val_len=len(found))

              if looks_like_real_key(found):
                yield Issue(
                  detector_id=self.option,
                  cvss3_vector=self.cvss,
                  confidence=IssueConfidence.FIRM,
                  summary='insecure cryptography: static keys',
                  info1=info1,
                  source=store.query().qualname_of(cl),
                  synopsis='Traces of cryptographic material has been found the application binary.',
                  description='''\
Traces of cryptographic material has been found in the application binary.  If cryptographic material is hardcoded, attackers can extract or replace them.
''',
                  solution='''\
Use a device or installation specific information, or obfuscate them.
'''
                )
              else:
                yield Issue(
                  detector_id=self.option,
                  cvss3_vector=self.cvss_nonkey,
                  confidence=IssueConfidence.TENTATIVE,
                  summary='Cryptographic constants detected',
                  info1=info1,
                  source=store.query().qualname_of(cl),
                  synopsis='Possible cryptographic constants have been found.',
                  description='''\
Possible cryptographic constants has been found in the application binary.
'''
                )
        except IndexError:
          pass

  def do_detect_case2(self):
    # XXX: Crude detection
    def should_be_secret(store, k, val):
      return any(x in store.query().qualname_of(k).lower() for x in ['inapp','billing','iab','sku','store','key'])

    pat = '^MI[IG][0-9A-Za-z+/=-]{32,}AQAB'
    with self.context.store() as store:
      for cl in store.query().consts(InvocationPattern('const-string', pat)):
        val = cl.p[1].v
        yield Issue(
          detector_id=self.option,
          cvss3_vector=self.cvss,
          confidence={True:IssueConfidence.FIRM, False:IssueConfidence.TENTATIVE}[should_be_secret(store, cl, val)],
          summary='insecure cryptography: static keys (2)',
          info1='"%(target_val)s" [%(target_val_len)d] (X.509)' % dict(target_val=val, target_val_len=len(val)),
          source=store.query().qualname_of(cl),
          synopsis='Traces of X.509 certificates has been found the application binary.',
          description='''\
Traces of X.509 certificates has been found in the application binary.  X.509 ceritificates describe public key materials.  Their notable uses include Google Play in-app billing identity.  If is hardcoded, attackers can extract or replace them.
''',
          solution='''\
Use a device or installation specific information, or obfuscate them.  Especially, do not use the stock implementation of in-app billing logic.
'''
        )
      for name, val in self.context.string_resources():
        if re.match(pat, val):
          yield Issue(
            detector_id=self.option,
            cvss3_vector=self.cvss,
            confidence=IssueConfidence.TENTATIVE,
            summary='insecure cryptography: static keys (2)',
            info1='"%(target_val)s" [%(target_val_len)d] (X.509)' % dict(target_val=val, target_val_len=len(val)),
            source='R.string.%s' % name,
            synopsis='Traces of X.509 certificates has been found the application binary.',
            description='''\
Traces of X.509 certificates has been found in the application binary.  X.509 ceritificates describe public key materials.  Their notable uses include Google Play in-app billing identity.  If is hardcoded, attackers can extract or replace them.
''',
            solution='''\
Use a device or installation specific information, or obfuscate them.  Especially, do not use the stock implementation of in-app billing logic.
'''
          )


class CryptoEcbDetector(Detector):
  option = 'crypto-ecb'
  description = 'Detects ECB mode ciphers'
  cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/'

  def do_detect(self):
    with self.context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-static', 'Ljavax/crypto/Cipher;->getInstance\(Ljava/lang/String;.*?\)')):
        try:
          target_val = DataFlows.solved_possible_constant_data_in_invocation(store, cl, 0)
          if any((('ECB' in x or '/' not in x) and 'RSA' not in x) for x in target_val):
            yield Issue(
              detector_id=self.option,
              cvss3_vector=self.cvss,
              confidence=IssueConfidence.CERTAIN,
              summary='insecure cryptography: cipher might be operating in ECB mode',
              info1=','.join(target_val),
              source=store.query().qualname_of(cl),
              synopsis='The application might be using ciphers in ECB mode.',
              description='''\
              The application might be using symmetric ciphers in ECB mode.  ECB mode is the most basic operating mode that independently transform data blocks.  Indepent transformation leaks information about distribution in plaintext.
''',
              solution='''\
Use CBC or CTR mode.
'''
            )
        except (DataFlows.NoSuchValueError):
          pass

class CryptoNonRandomXorDetector(Detector):
  option = 'crypto-xor'
  description = 'Detects Vernum cipher usage with static keys'
  cvss = 'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/'

  def do_detect(self):
    with self.context.store() as store:
      for cl in store.query().ops_of('xor-int/lit8'):
        target_val = int(cl.p[2].v, 16)
        if (cl.p[0].v == cl.p[1].v) and target_val > 1:
          yield Issue(
            detector_id=self.option,
            cvss3_vector=self.cvss,
            confidence=IssueConfidence.FIRM,
            summary='insecure cryptography: non-random XOR cipher',
            info1='0x%02x' % target_val,
            source=store.query().qualname_of(cl)
          )
