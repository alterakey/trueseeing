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

from trueseeing.context import warning_on
from trueseeing.flow.code import OpMatcher, InvocationPattern
from trueseeing.flow.data import DataFlows
from trueseeing.signature.base import Detector

class CryptoStaticKeyDetector(Detector):
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

  def detect(self):
    marks = []
    marked = []

    consts = set()
    for cl in self.context.analyzed_classes():
      for k in OpMatcher(cl.ops, InvocationPattern('const-string', r'^[0-9A-Za-z+/=]{8,}=?$')).matching():
        val = k.p[1].v
        try:
          raw = base64.b64decode(val)
        except ValueError:
          raw = None
        if (self.assumed_randomness_of(val) > 0.7) or (raw is not None and (len(raw) % 8 == 0 and self.assumed_randomness_of(raw) > 0.5)):
          consts.add(val)

    for cl in self.context.analyzed_classes():
      for k in OpMatcher(cl.ops, InvocationPattern('invoke-', 'Ljavax/crypto|Ljava/security')).matching():
        try:
          #pprint.pprint(DataFlows.into(k))
          for nr in range(len(DataFlows.decoded_registers_of(k.p[0]))):
            for found in consts & DataFlows.solved_possible_constant_data_in_invocation(k, nr):
              marks.append(dict(name=self.context.class_name_of_dalvik_class_type(cl.qualified_name()), method=k.method_, op=k, target_val=found))
        except IndexError:
          pass

    o = []
    for m in marks:
      try:
        decoded = base64.b64decode(m['target_val'])
        o.append(warning_on(name=m['name'] + '#' + m['method'].v.v, row=0, col=0, desc='insecure cryptography: static keys: "%s" [%d] (base64; "%s" [%d])' % (m['target_val'], len(m['target_val']), binascii.hexlify(decoded).decode('ascii'), len(decoded)), opt='-Wcrypto-static-keys'))
      except (ValueError, binascii.Error):
        o.append(warning_on(name=m['name'] + '#' + m['method'].v.v, row=0, col=0, desc='insecure cryptography: static keys: "%s" [%d]' % (m['target_val'], len(m['target_val'])), opt='-Wcrypto-static-keys'))

    return o

class CryptoEcbDetector(Detector):
  def detect(self):
    marks = []
    for cl in self.context.analyzed_classes():
      for k in OpMatcher(cl.ops, InvocationPattern('invoke-static', 'Ljavax/crypto/Cipher;->getInstance\(Ljava/lang/String;.*?\)')).matching():
        marks.append(dict(name=self.context.class_name_of_dalvik_class_type(cl.qualified_name()), method=k.method_, op=k))

    for m in marks:
      try:
        m['target_val'] = DataFlows.solved_possible_constant_data_in_invocation(m['op'], 0)
      except (DataFlows.NoSuchValueError):
        pass

    o = []
    for m in (r for r in marks if any(('ECB' in x or '/' not in x) for x in r.get('target_val', []))):
      o.append(warning_on(name=m['name'] + '#' + m['method'].v.v, row=0, col=0, desc='insecure cryptography: cipher might be operating in ECB mode: %s' % m['target_val'], opt='-Wcrypto-ecb'))

    return o
  
def check_crypto_static_keys(context):
  return CryptoStaticKeyDetector(context).detect()

def check_crypto_ecb(context):
  return CryptoEcbDetector(context).detect()
