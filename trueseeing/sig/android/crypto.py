from __future__ import annotations
from typing import TYPE_CHECKING

import asyncio
import re
import math
from functools import cache

from trueseeing.core.model.sig import SignatureMixin
from trueseeing.core.android.model.code import InvocationPattern
from trueseeing.core.android.analysis.flow import DataFlow

if TYPE_CHECKING:
  from typing import Dict, Iterable, Optional, Any
  from trueseeing.core.android.model.code import Op
  from trueseeing.core.android.store import Store
  from trueseeing.api import Signature, SignatureHelper, SignatureMap

class CryptoStaticKeyDetector(SignatureMixin):
  _id = 'crypto-static-keys'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N/'
  _cvss_nonkey = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/'
  _cvss_pubkey = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:N/'
  _cvss_privkey = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return CryptoStaticKeyDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id: dict(e=self.detect, d='Detects cryptographic function usage with static keys')}

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
      yield from range(len(DataFlow.decoded_registers_of_set(k.p[0])))

  async def detect(self) -> None:
    await asyncio.gather(self._do_detect_case1(), self._do_detect_case2())

  async def _do_detect_case1(self) -> None:
    import base64
    import binascii

    def looks_like_real_key(k: str) -> bool:
      # XXX: silly
      return len(k) >= 8 and not any(x in k for x in ('Padding', 'SHA1', 'PBKDF2', 'Hmac', 'emulator'))

    pat_case2 = '^M[C-I][0-9A-Za-z+/=-]{48,}'
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.invocations(InvocationPattern('invoke-', '^Ljavax?.*/(SecretKey|(Iv|GCM)Parameter|(PKCS8|X509)EncodedKey)Spec|^Ljavax?.*/MessageDigest;->(update|digest)')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      try:
        for nr in self._important_args_on_invocation(cl):
          for found in DataFlow(q).solved_possible_constant_data_in_invocation(cl, nr):
            try:
              if re.search(pat_case2, found):
                continue

              decoded = base64.b64decode(found)
              info0 = '"{target_val}" [{target_val_len}] (base64; "{decoded_val}" [{decoded_val_len}])'.format(target_val=found, target_val_len=len(found), decoded_val=binascii.hexlify(decoded).decode('ascii'), decoded_val_len=len(decoded))
            except (ValueError, binascii.Error):
              info0 = f'"{found}" [{len(found)}]'

            if looks_like_real_key(found):
              self._helper.raise_issue(self._helper.build_issue(
                sigid=self._id,
                cvss=self._cvss,
                title='insecure cryptography: static keys detected',
                info0=info0,
                info1=q.method_call_target_of(cl),
                aff0=qn,
                summary='Traces of cryptographic material has been found the application binary.',
                desc='''\
Traces of cryptographic material has been found in the application binary.  If cryptographic material is hardcoded, attackers can extract or replace them.
''',
                sol='''\
Use a device or installation specific information, or obfuscate them.
'''
              ))
            else:
              self._helper.raise_issue(self._helper.build_issue(
                sigid=self._id,
                cvss=self._cvss_nonkey,
                cfd='tentative',
                title='Cryptographic constants detected',
                info0=info0,
                info1=q.method_call_target_of(cl),
                aff0=qn,
                summary='Possible cryptographic constants have been found.',
                desc='''\
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

    pat = '^M[C-I][0-9A-Za-z+/=-]{48,}'
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.consts(InvocationPattern('const-string', pat)):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      val = cl.p[1].v
      typ = self._inspect_value_type(val)
      param = self._build_template_params(val, typ)
      self._helper.raise_issue(self._helper.build_issue(
        sigid=self._id,
        cvss=self._cvss_nonkey if param['nonkey'] else (self._cvss_pubkey if not param['private'] else self._cvss_privkey),
        cfd='certain' if typ else ('firm' if should_be_secret(store, cl, val) else 'tentative'),
        title=('insecure cryptography: {key} detected' if not param['nonkey'] else '{key} detected').format(**param),
        info0='"{val}" [{len}] ({keytype})'.format(**param),
        aff0=qn,
        summary='Traces of {key}s have been found the application binary.'.format(**param),
        desc='''\
Traces of {key}s have been found in the application binary.  If they are hardcoded, attackers can extract or replace them.'''.format(**param),
        sol='''\
Use a device or installation specific information, or obfuscate them.
'''
      ))

    for name, val in context.string_resources():
      if re.match(pat, val):
        typ = self._inspect_value_type(val)
        param = self._build_template_params(val, typ)
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cvss=self._cvss_nonkey if param['nonkey'] else (self._cvss_pubkey if not param['private'] else self._cvss_privkey),
          cfd='certain' if typ else 'firm',
          title=('insecure cryptography: {key} detected' if param['nonkey'] else '{key} detected').format(**param),
          info0='"{val}" [{len}] ({keytype})'.format(**param),
          aff0=f'R.string.{name}',
          summary='Traces of {key}s have been found the application binary.'.format(**param),
          desc='''\
Traces of {key}s have been found in the application binary.  If they are hardcoded, attackers can extract or replace them.'''.format(**param),
          sol='''\
Use a device or installation specific information, or obfuscate them.
'''
        ))

  def _build_template_params(self, val: str, typ: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    param = dict(
      nonkey=True,
      val=val,
      len=len(val),
      key='cryptographic material',
      keytype='ASN.1',
    )
    if typ:
      if typ['type'] == 'cert':
        param.update(dict(
          private=False,
          key='X.509 certificate',
          keytype=('{}-bit {} with {}, subject CN: {}, issuer CN: {}{})'.format(typ['bits'], typ['algo'], typ['hashalgo'], typ['subject'], typ['issuer'], ' [self-signed]' if typ['selfsign'] != 'no' else ''))
        ))
      elif typ['type'] == 'pub':
        param.update(dict(
          nonkey=False,
          private=False,
          key='public key',
          keytype=('{}-bit {}'.format(typ['bits'], typ['algo'])),
        ))
      elif typ['type'] == 'priv':
        param.update(dict(
          nonkey=False,
          private=True,
          key='private key',
          keytype=('{}-bit {}'.format(typ['bits'] if isinstance(typ['bits'], int) else '~{:.01f}'.format(typ['bits']), typ['algo'])),
        ))
    return param

  @cache
  def _inspect_value_type(self, v: str) -> Optional[Dict[str, Any]]:
    from base64 import b64decode
    from asn1crypto.x509 import Certificate
    from asn1crypto.keys import PublicKeyInfo, PrivateKeyInfo, RSAPrivateKey
    r = b64decode(v)
    try:
      cert = Certificate.load(r)
      return dict(type='cert', algo=self._read_algo(cert.public_key), hashalgo=self._read_algo(cert.hash_algo), bits=cert.public_key.bit_size, subject=cert.subject.native.get('common_name', '(unknown)'), issuer=cert.issuer.native.get('common_name', '(unknown)'), selfsign=cert.self_signed)
    except ValueError:
      pass
    try:
      pubkey = PublicKeyInfo.load(r)
      return dict(type='pub', algo=self._read_algo(pubkey), bits=pubkey.bit_size)
    except ValueError:
      pass
    try:
      privkey0 = PrivateKeyInfo.load(r)
      return dict(type='priv', algo=self._read_algo(privkey0), bits=privkey0.bit_size)
    except ValueError:
      pass
    try:
      from math import log
      privkey1 = RSAPrivateKey.load(r)
      return dict(type='priv', algo=self._read_algo('rsa'), bits=log(privkey1['modulus'].native) / log(2))
    except ValueError:
      pass
    return None

  @cache
  def _read_algo(self, x: Any) -> str:
    if isinstance(x, str):
      return x.upper()
    else:
      algo = str(x.algorithm)
      if algo != 'ec':
        return algo.upper()
      else:
        if x.curve[0] == 'named':
          return '{} [{}]'.format(algo.upper(), str(x.curve[1]))
        else:
          return '{}'.format(algo.upper())


class CryptoEcbDetector(SignatureMixin):
  _id = 'crypto-ecb'
  _cvss = 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return CryptoEcbDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id: dict(e=self.detect, d='Detects ECB mode ciphers')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.invocations(InvocationPattern('invoke-static', r'Ljavax/crypto/Cipher;->getInstance\(Ljava/lang/String;.*?\)')):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      try:
        target_val = DataFlow(q).solved_possible_constant_data_in_invocation(cl, 0)
        if any((('ECB' in x or '/' not in x) and 'RSA' not in x) for x in target_val):
          self._helper.raise_issue(self._helper.build_issue(
            sigid=self._id,
            cvss=self._cvss,
            cfd='certain',
            title='insecure cryptography: cipher might be operating in ECB mode',
            info0=','.join(target_val),
            aff0=qn,
            summary='The application might be using ciphers in ECB mode.',
            desc='''\
            The application might be using symmetric ciphers in ECB mode.  ECB mode is the most basic operating mode that independently transform data blocks.  Indepent transformation leaks information about distribution in plaintext.
''',
            sol='''\
Use CBC or CTR mode.
'''
          ))
      except (DataFlow.NoSuchValueError):
        pass

class CryptoNonRandomXorDetector(SignatureMixin):
  _id = 'crypto-xor'
  _cvss = 'CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/'

  @staticmethod
  def create(helper: SignatureHelper) -> Signature:
    return CryptoNonRandomXorDetector(helper)

  def get_sigs(self) -> SignatureMap:
    return {self._id: dict(e=self.detect, d='Detects Vernum cipher usage with static keys')}

  async def detect(self) -> None:
    context = self._helper.get_context('apk')
    store = context.store()
    q = store.query()
    for cl in q.ops_of('xor-int/lit8'):
      qn = q.qualname_of(cl)
      if context.is_qualname_excluded(qn):
        continue
      target_val = int(cl.p[2].v, 16)
      if (cl.p[0].v == cl.p[1].v) and target_val > 1:
        self._helper.raise_issue(self._helper.build_issue(
          sigid=self._id,
          cvss=self._cvss,
          title='insecure cryptography: non-random XOR cipher',
          info0=f'0x{target_val:02x}',
          aff0=q.qualname_of(cl)
        ))
