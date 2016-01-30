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

from trueseeing.flow.code import OpMatcher, InvocationPattern
from trueseeing.flow.data import DataFlows
from trueseeing.signature.base import Detector

log = logging.getLogger(__name__)

class CryptoStaticKeyDetector(Detector):
  option = 'crypto-static-keys'
  
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

  def do_detect(self):
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
              try:
                decoded = base64.b64decode(found)
                yield self.warning_on(name='%(name)s#%(method)s' % dict(name=self.context.class_name_of_dalvik_class_type(cl.qualified_name()), method=k.method_.v.v), row=0, col=0, desc='insecure cryptography: static keys: "%(target_val)s" [%(target_val_len)d] (base64; "%(decoded_val)s" [%(decoded_val_len)d])' % dict(target_val=found, target_val_len=len(found), decoded_val=binascii.hexlify(decoded).decode('ascii'), decoded_val_len=len(decoded)), opt='-Wcrypto-static-keys')
              except (ValueError, binascii.Error):
                yield self.warning_on(name='%(name)s#%(method)s' % dict(name=self.context.class_name_of_dalvik_class_type(cl.qualified_name()), method=k.method_.v.v), row=0, col=0, desc='insecure cryptography: static keys: "%(target_val)s" [%(target_val_len)d]' % dict(target_val=found, target_val_len=len(found)), opt='-Wcrypto-static-keys')
        except IndexError:
          pass

class CryptoEcbDetector(Detector):
  option = 'crypto-ecb'
  
  def do_detect(self):
    for cl in self.context.analyzed_classes():
      for k in OpMatcher(cl.ops, InvocationPattern('invoke-static', 'Ljavax/crypto/Cipher;->getInstance\(Ljava/lang/String;.*?\)')).matching():
        try:
          target_val = DataFlows.solved_possible_constant_data_in_invocation(k, 0)
          if any(('ECB' in x or '/' not in x) for x in target_val):
            yield self.warning_on(name='%(name)s#%(method)s' % dict(name=self.context.class_name_of_dalvik_class_type(cl.qualified_name()), method=k.method_.v.v), row=0, col=0, desc='insecure cryptography: cipher might be operating in ECB mode: %s' % target_val, opt='-Wcrypto-ecb')
        except (DataFlows.NoSuchValueError):
          pass
