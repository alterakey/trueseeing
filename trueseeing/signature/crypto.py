# Vulnerabilities:
# * Cryptography: Insecure cryptography: Static keys
# * Cryptography: Insecure cryptography: ECB
# * Cryptography: Insecure cryptography: CBC with fixed key/IV
# * Cryptography: Insecure cryptography: CFB/OFB with fixed key/IV
# * Cryptography: Insecure cryptography: CTR with same counter and key
# * Cryptography: Insecure cryptography: non-random XOR cipher
# * Cryptography: Insecure cryptography: implicit trust on non-authenticated data

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
from trueseeing.signature.base import Detector, IssueConfidence, IssueSeverity

log = logging.getLogger(__name__)

class CryptoStaticKeyDetector(Detector):
  option = 'crypto-static-keys'
  cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/'

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
      return len(k) >= 8 and 'Padding' not in k

    with self.context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-', 'Ljavax?.*/(SecretKey|(Iv|GCM)Parameter|(PKCS8|X509)EncodedKey)Spec|Ljavax?.*/MessageDigest;->(update|digest)')):
        try:
          for nr in self.important_args_on_invocation(cl):
            for found in DataFlows.solved_possible_constant_data_in_invocation(store, cl, nr):
              try:
                decoded = base64.b64decode(found)
                yield self.issue({True:IssueConfidence.FIRM, False:IssueConfidence.TENTATIVE}[looks_like_real_key(found)], self.cvss, 'insecure cryptography: static keys', '"%(target_val)s" [%(target_val_len)d] (base64; "%(decoded_val)s" [%(decoded_val_len)d])' % dict(target_val=found, target_val_len=len(found), decoded_val=binascii.hexlify(decoded).decode('ascii'), decoded_val_len=len(decoded)), None, None, store.query().qualname_of(cl))
              except (ValueError, binascii.Error):
                yield self.issue({True:IssueConfidence.FIRM, False:IssueConfidence.TENTATIVE}[looks_like_real_key(found)], self.cvss, 'insecure cryptography: static keys', '"%(target_val)s" [%(target_val_len)d]' % dict(target_val=found, target_val_len=len(found)), None, None, store.query().qualname_of(cl))
        except IndexError:
          pass

  def do_detect_case2(self):
    # XXX: Crude detection
    def should_be_secret(store, k, val):
      return any(x in store.query().qualname_of(k).lower() for x in ['inapp','billing','iab','sku','store'])

    pat = '^MI[IG][0-9A-Za-z+/=-]{32,}AQAB'
    with self.context.store() as store:
      for cl in store.query().consts(InvocationPattern('const-string', pat)):
        val = cl.p[1].v
        yield self.issue({True:IssueConfidence.FIRM, False:IssueConfidence.TENTATIVE}[should_be_secret(store, cl, val)], self.cvss, 'insecure cryptography: static keys', '"%(target_val)s" [%(target_val_len)d] (X.509; Google Play In App Billing Key)' % dict(target_val=val, target_val_len=len(val)), None, None, store.query().qualname_of(cl))
      for name, val in self.context.string_resources():
        if re.match(pat, val):
          yield self.issue(IssueConfidence.TENTATIVE, 'insecure cryptography: static keys', '"%(target_val)s" [%(target_val_len)d] (X.509; Google Play In App Billing Key)' % dict(target_val=val, target_val_len=len(val)), None, None, 'R.string.%s' % name)


class CryptoEcbDetector(Detector):
  option = 'crypto-ecb'
  cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/'

  def do_detect(self):
    with self.context.store() as store:
      for cl in store.query().invocations(InvocationPattern('invoke-static', 'Ljavax/crypto/Cipher;->getInstance\(Ljava/lang/String;.*?\)')):
        try:
          target_val = DataFlows.solved_possible_constant_data_in_invocation(store, cl, 0)
          if any(('ECB' in x or '/' not in x) for x in target_val):
            yield self.issue(IssueConfidence.CERTAIN, self.cvss, 'insecure cryptography: cipher might be operating in ECB mode', ','.join(target_val), None, None, store.query().qualname_of(cl))
        except (DataFlows.NoSuchValueError):
          pass

class CryptoNonRandomXorDetector(Detector):
  option = 'crypto-xor'
  cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/'

  def do_detect(self):
    with self.context.store() as store:
      for cl in store.query().ops_of('xor-int/lit8'):
        target_val = int(cl.p[2].v, 16)
        if (cl.p[0].v == cl.p[1].v) and target_val > 1:
          yield self.issue(IssueConfidence.FIRM, self.cvss, 'insecure cryptography: non-random XOR cipher', '0x%02x' % target_val, None, None, store.query().qualname_of(cl))
