from __future__ import annotations
from typing import TYPE_CHECKING

import lxml.etree as ET
import os
import re
from functools import cache

from pubsub import pub

from trueseeing.core.ui import ui
from trueseeing.core.env import get_cache_dir, get_cache_dir_v0, get_cache_dir_v1
from trueseeing.core.context import Context, Fingerprint

if TYPE_CHECKING:
  from typing import List, Any, Iterable, Tuple, Optional, ClassVar, Set, AsyncIterator, Iterator, Mapping
  from trueseeing.core.context import ContextType, ContextInfo
  from trueseeing.core.android.asm import APKDisassembler
  from trueseeing.core.android.store import APKStore
  from trueseeing.core.android.model import XAPKManifest, Call

class PackageNameReader:
  @cache
  def read(self, path: str) -> str:
    if path.endswith('.apk'):
      from pyaxmlparser import APK
      apk = APK(path)
      return apk.packagename # type: ignore[no-any-return]
    elif path.endswith('.xapk'):
      from zipfile import ZipFile
      with ZipFile(path) as zf:
        from json import loads
        manif: XAPKManifest = loads(zf.read('manifest.json'))
        vers = manif['xapk_version']
        if str(vers) != '2':
          raise ValueError(f'invalid xapk manifest: {vers}')
        pkg = manif['package_name']
        return pkg
    else:
      raise ValueError('format unknown')

class APKContext(Context):
  _store: Optional[APKStore] = None
  _type: ClassVar[Set[ContextType]] = {'apk', 'file'}
  _package_reader = PackageNameReader()
  _fp = Fingerprint()

  def invalidate(self) -> None:
    super().invalidate()
    if self._store:
      self._store.invalidate()
      self._store = None
    self.disassembled_classes.cache_clear()
    self.disassembled_resources.cache_clear()
    self.disassembled_assets.cache_clear()
    self._string_resource_files.cache_clear()
    self._xml_resource_files.cache_clear()
    self._fp.get.cache_clear()

  def _get_workdir(self) -> str:
    path = self._get_workdir_v3()
    if os.path.isdir(path):
      return path
    else:
      fp = self._get_fingerprint()
      paths = dict(v0=self._get_workdir_v0(fp), v1=self._get_workdir_v1(fp), v2=self._get_workdir_v2(fp))
      for vers,trypath in paths.items():
        if os.path.isdir(trypath):
          ui.warn(f'cpntext uses old path ({vers}), consider moving it to {path}')
          return trypath
      else:
        return path

  def _get_workdir_v3(self) -> str:
    from hashlib import sha256
    ctx_id = sha256((self._path + ':' + self.get_package_name()).encode('utf-8')).hexdigest()
    return os.path.join(get_cache_dir(), ctx_id)

  def _get_workdir_v2(self, fp: str) -> str:
    return os.path.join(get_cache_dir(), fp)

  def _get_workdir_v1(self, fp: str) -> str:
    return os.path.join(get_cache_dir_v1(self._path), f'.trueseeing2-{fp}')

  def _get_workdir_v0(self, fp: str) -> str:
    return os.path.join(get_cache_dir_v0(), fp)

  def store(self) -> APKStore:
    if self._store is None:
      assert self.wd is not None
      from trueseeing.core.android.store import APKStore
      self._store = APKStore(self.wd)
    return self._store

  def _get_type(self) -> Set[ContextType]:
    return self._type

  def _get_size(self) -> Optional[int]:
    return os.stat(self._path).st_size

  def _get_fingerprint(self) -> str:
    return self._fp.get(self._path)

  async def _recheck_schema(self) -> None:
    from trueseeing.core.android.store import APKStore
    APKStore.require_valid_schema_on(self.wd)

  async def _get_disassembler(self) -> APKDisassembler:
    from trueseeing.core.android.asm import APKDisassembler
    return APKDisassembler(self)

  async def _analyze(self, level: int) -> None:
    from time import time

    at = time()

    await self._analyze_dalvik(level)
    await self._analyze_native(level)

    pub.sendMessage('progress.core.analysis.done', t=time()-at)

  async def _analyze_dalvik(self, level: int) -> None:
    pub.sendMessage('progress.core.context.disasm.begin')
    disasm = await self._get_disassembler()
    await disasm.disassemble(level)
    pub.sendMessage('progress.core.context.disasm.done')

    if level > 3:
      import time
      from io import StringIO

      started = time.time()
      pat = 'smali/%.smali'
      with self.store().query().scoped() as q:
        total = q.file_count(pat)
        pub.sendMessage('progress.core.analysis.smali.begin', total=total)
        with q.db as c:
          def _addr(nr: int, ln: int) -> int:
            return (nr << 24 | ln)

          def _addr_floor(nr: int) -> int:
            return _addr(nr, 0)

          def _addr_ceil(nr: int) -> int:
            return _addr_floor(nr+1) - 1

          nr = 0
          c.execute('create temporary table _tmp_ops (addr integer not null primary key, l varchar not null)')
          c.execute('create temporary table _tmp_ops_map (addr integer primary key, map_id integer)')
          c.execute('create temporary table _tmp_xref (addr integer not null, insn varchar not null, val varchar not null, unique (addr, insn, val))')

          for n, b in q.file_enum(pat):
            t = b.decode('utf-8')
            m = re.search(r'^\.class.* (L.*?;)', t)
            assert m is not None, t
            class_name = m.group(1)
            m = re.search(r'^\.super (L.*?;)', t, re.MULTILINE)
            assert m is not None
            extends = m.group(1)
            implements = [m.group(1) for m in re.finditer(r'^\.implements (L.*?;)$', t, re.MULTILINE)]
            c.execute('insert into class_rel(class, super) values (:class_name, :extends)', dict(class_name=class_name, extends=extends))
            for impl in implements:
              c.execute('insert into class_rel(class, impl) values (:class_name, :impl)', dict(class_name=class_name, impl=impl))

            c.execute('insert into map(low, high, class) values (:low, :high, :class_name)', dict(low=_addr_floor(nr), high=_addr_ceil(nr), class_name=class_name))
            method_seen: Optional[Tuple[int, str]] = None
            for ln, l in enumerate(StringIO(t)):
              addr = _addr(nr, ln)
              l = l.rstrip('\n')
              if not l or ' .line ' in l or l.startswith('.source '):
                continue
              c.execute('insert into _tmp_ops(addr, l) values (:addr, :l)', dict(addr=addr, l=l))
              if not method_seen:
                m = re.search(r'^\.method .*? ([^ ]+)$', l)
                if m:
                  method_seen = ln, m.group(1)
              else:
                m = re.search(r'^  +((?:invoke|[si]put|const)\S+)', l)
                if m:
                  insn = m.group(1)
                  mv = re.search(r', (".*"|\S+)(?: +# .+?)?$', l)
                  assert mv, l
                  c.execute('insert into _tmp_xref (addr, insn, val) values (:addr, :insn, :val)', dict(addr=addr, insn=insn, val=mv.group(1)))
                else:
                  if l.startswith(r'.end method'):
                    start, name = method_seen
                    c.execute('insert into map(low, high, class, method) values (:low, :high, :class_name, :method_name)', dict(low=_addr(nr, start), high=addr, class_name=class_name, method_name=name))
                    method_seen = None

            nr += 1
            pub.sendMessage('progress.core.analysis.smali.analyzing', nr=nr)

          pub.sendMessage('progress.core.analysis.smali.analyzed')

          nr_ops = 0
          for nr, in c.execute('select count(1) from _tmp_ops'):
            nr_ops = nr
            pub.sendMessage('progress.core.analysis.smali.summary', ops=nr)

          nr_classes = 0
          for nr, in c.execute('select count(1) from map where method is null'):
            nr_classes = nr
            pub.sendMessage('progress.core.analysis.smali.summary', ops=nr_ops, classes=nr_classes)

          nr_methods = 0
          for nr, in c.execute('select count(1) from map where method is not null'):
            nr_methods = nr
            pub.sendMessage('progress.core.analysis.smali.summary', ops=nr_ops, classes=nr_classes, methods=nr_methods)

          pub.sendMessage('progress.core.analysis.smali.finalizing')

          for addr, insn, val in c.execute('select addr, insn, val from _tmp_xref'):
            if insn.startswith('const'):
              c.execute('insert into xref_const (addr, insn, sym) values (:addr, :insn, :sym)', dict(addr=addr, insn=insn, sym=val if not val.startswith('"') else val[1:-1]))
            else:
              nc = val.split('->')
              assert len(nc) == 2
              if insn.startswith('invoke'):
                assert '(' in nc[1]
                c.execute('insert into xref_invoke (addr, insn, sym, target) values (:addr, :insn, :sym, (select low from map where class=:cn and method=:mn))', dict(addr=addr, insn=insn, sym=val, cn=nc[0], mn=nc[1]))
              else:
                assert '(' not in nc[1]
                if insn.startswith('sput'):
                  c.execute('insert into xref_sput (addr, insn, sym) values (:addr, :insn, :sym)', dict(addr=addr, insn=insn, sym=val))
                elif insn.startswith('iput'):
                  c.execute('insert into xref_iput (addr, insn, sym) values (:addr, :insn, :sym)', dict(addr=addr, insn=insn, sym=val))

          c.execute('insert into _tmp_ops_map select A.addr,B.id from _tmp_ops as A join map as B on (A.addr between B.low and B.high) where B.method is null')
          c.execute('insert or replace into _tmp_ops_map select A.addr,B.id from _tmp_ops as A join map as B on (A.addr between B.low and B.high) where B.method is not null')
          c.execute('insert into ops (addr, l, map_id) select addr, l, map_id from _tmp_ops join _tmp_ops_map using (addr)')
          c.execute('analyze')
          pub.sendMessage('progress.core.analysis.smali.done', t=time.time() - started)

  async def _analyze_native(self, level: int) -> None:
    if level > 2:
      tarpath = os.path.join(os.path.dirname(self._path), 'disasm.tar.gz')
      if not os.path.exists(tarpath):
        ui.warn(f'skipping native code analysis; prepare {tarpath}')
        return

      from time import time
      at = time()

      with self.store().query().scoped() as q:
        pub.sendMessage('progress.core.analysis.nat.begin')
        import tarfile
        with tarfile.open(tarpath) as tf:
          q.file_put_batch(dict(path=i.name, blob=tf.extractfile(i).read(), z=True) for i in tf.getmembers() if (i.isreg() or i.islnk())) # type:ignore[union-attr]

        if level > 3:
          pub.sendMessage('progress.core.analysis.nat.analyzing')
          from trueseeing.core.android.analyze.nat import analyze_api_in

          def _as_call(g: Iterator[Mapping[str, Any]]) -> Iterator[Call]:
            for e in g:
              typ = e['typ']
              lang = e['lang']
              sect, offs = e['origin'].split('+')
              yield dict(
                path=e['fn'],
                sect=sect,
                offs=int(offs.strip(), 16),
                priv=(typ == 'private'),
                cpp=(lang == 'cpp'),
                target=e['call']
              )

          q.call_add_batch(_as_call(analyze_api_in(q.file_enum('lib/%'))))
          pub.sendMessage('progress.core.analysis.nat.summary', calls=q.call_count())

      pub.sendMessage('progress.core.analysis.nat.done', t=time() - at)

  def get_package_name(self) -> str:
    return self._package_reader.read(self.target)

  async def _get_info(self, extended: bool) -> AsyncIterator[ContextInfo]:
    async for m in super()._get_info(extended):
      yield m

    level = self.get_analysis_level()
    if level > 0:
      store = self.store()
      manif = self.parsed_manifest()
      yield dict(
        pkg=self.get_package_name(),
        ver='{} ({})'.format(
          manif.attrib['{http://schemas.android.com/apk/res/android}versionName'],
          manif.attrib['{http://schemas.android.com/apk/res/android}versionCode']
        ),
        perms=len(list(self.permissions_declared())),
        activs=len(list(manif.xpath('.//activity'))),
        servs=len(list(manif.xpath('.//service'))),
        recvs=len(list(manif.xpath('.//receiver'))),
        provs=len(list(manif.xpath('.//provider'))),
      )
      yield {'int-flts':len(list(manif.xpath('.//intent-filter')))}
      if level > 3:
        with store.db as c:
          for nr, in c.execute('select count(1) from class_rel where super regexp :pat', dict(pat='^Landroid.*Fragment(Compat)?;$')):
            yield dict(frags=nr)
      for e in manif.xpath('.//application'):
        boolmap = {True:'true', False:'false', 'true':'true', 'false':'false'}
        yield {
          'debuggable?':boolmap.get(e.attrib.get('{http://schemas.android.com/apk/res/android}debuggable', 'false'), '?'),
          'backupable?':boolmap.get(e.attrib.get('{http://schemas.android.com/apk/res/android}allowBackup', 'false'), '?'),
          'netsecconf?':boolmap.get(e.attrib.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig') is not None, '?'),
        }
      if manif.xpath('.//uses-sdk'):
        for e in manif.xpath('.//uses-sdk'):
          yield {
            'api min':int(e.attrib.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '1')),
            'api tgt':int(e.attrib.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '1')),
          }
      else:
        ui.warn('cannot determine min/target sdk version')
        yield {
          'api min':'?',
          'api tgt':'?',
        }
      if level == 3:
        with store.query().scoped() as q:
          yield dict(classes='~{}'.format(q.file_count('smali/%')))
      elif level > 3:
        with store.db as c:
          for nr, in c.execute('select count(1) from analysis_issues'):
            yield dict(issues='{}{}'.format(nr, ('' if nr else ' (not scanned yet?)')))
          for nr, in c.execute('select count(1) from ops'):
            yield dict(ops='{}'.format(nr))
          for nr, in c.execute('select count(1) from map where method is null'):
            yield dict(classes='{}'.format(nr))
          for nr, in c.execute('select count(1) from map where method is not null'):
            yield dict(methods='{}'.format(nr))

    if extended:
      from subprocess import CalledProcessError
      from trueseeing.core.android.device import AndroidDevice
      dev = AndroidDevice()
      try:
        build = (await dev.invoke_adb('shell getprop ro.build.fingerprint', catch_stderr=True)).rstrip()
        yield {
          'device?': 'yes ({})'.format(build),
        }
      except CalledProcessError as e:
        cause = e.stderr.decode().splitlines()[-1]
        if cause.startswith('adb: no '):
          yield {
            'device?': 'no',
          }
        else:
          yield {
            'device?': '? ({})'.format(cause)
          }

  def parsed_manifest(self, patched: bool = False) -> Any:
    return self.store().query().file_get_xml('AndroidManifest.xml', patched=patched)

  def manifest_as_xml(self, manifest: Any) -> bytes:
    assert manifest is not None
    return ET.tostring(manifest) # type: ignore[no-any-return]

  def get_target_sdk_version(self) -> int:
    manif = self.parsed_manifest()
    e = manif.xpath('.//uses-sdk')[0]
    return int(e.attrib.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '1'))

  # FIXME: Handle invalid values
  def get_min_sdk_version(self) -> int:
    manif = self.parsed_manifest()
    e = manif.xpath('.//uses-sdk')[0]
    return int(e.attrib.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '1'))

  @cache
  def disassembled_classes(self) -> List[str]:
    return list(self.store().query().file_find('smali%.smali'))

  @cache
  def disassembled_resources(self) -> List[str]:
    return list(self.store().query().file_find('%/res/%.xml'))

  @cache
  def disassembled_assets(self) -> List[str]:
    return list(self.store().query().file_find('root/%/assets/%'))

  def source_name_of_disassembled_class(self, fn: str) -> str:
    return os.path.join(*fn.split('/')[2:])

  def dalvik_type_of_disassembled_class(self, fn: str) -> str:
    return 'L{};'.format((self.source_name_of_disassembled_class(fn).replace('.smali', '')))

  def source_name_of_disassembled_resource(self, fn: str) -> str:
    return os.path.join(*fn.split('/')[3:])

  def class_name_of_dalvik_class_type(self, dc: str) -> str:
    return re.sub(r'^L|;$', '', dc).replace('/', '.')

  def permissions_declared(self) -> Iterable[Any]:
    yield from self.parsed_manifest().xpath('//uses-permission/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android'))

  @cache
  def _string_resource_files(self) -> List[str]:
    return list(self.store().query().file_find('%/res/values/%strings%'))

  def string_resources(self) -> Iterable[Tuple[str, str]]:
    for _, o in self.store().query().file_enum('%/res/values/%strings%'):
      yield from ((c.attrib['name'], c.text) for c in ET.fromstring(o, parser=ET.XMLParser(recover=True)).xpath('//resources/string') if c.text)

  @cache
  def _xml_resource_files(self) -> List[str]:
    return list(self.store().query().file_find('%/res/xml/%.xml'))

  def xml_resources(self) -> Iterable[Tuple[str, Any]]:
    for fn, o in self.store().query().file_enum('%/res/xml/%.xml'):
      yield (fn, ET.fromstring(o, parser=ET.XMLParser(recover=True)))

  def is_qualname_excluded(self, qualname: Optional[str]) -> bool:
    if qualname is not None:
      return any([re.match(f'L{x}', qualname) for x in self.excludes])
    else:
      return False

class XAPKContext(APKContext):
  _disasm: Optional[APKDisassembler] = None
  _type: ClassVar[Set[ContextType]] = {'xapk'}

  async def _get_disassembler(self) -> APKDisassembler:
    assert self._disasm
    return self._disasm

  async def _analyze(self, level: int) -> None:
    from shlex import quote
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(dir=self.wd) as td:
      from trueseeing.core.tools import invoke_streaming
      from trueseeing.core.android.tools import toolchains
      outfile = os.path.join(td, 'merged.apk')
      with toolchains() as tc:
        async for l in invoke_streaming('java -jar {apkeditor} m -i {target} -o {outfile}'.format(
            apkeditor=tc['apkeditor'],
            target=quote(self.target),
            outfile=outfile,
        )):
          ui.info(l.decode())
      try:
        from trueseeing.core.android.asm import APKDisassembler
        self._disasm = APKDisassembler(self, outfile)
        return await super()._analyze(level)
      finally:
        self._disasm = None

  def _get_type(self) -> Set[ContextType]:
    return super()._type | self._type

  async def _get_info(self, extended: bool) -> AsyncIterator[ContextInfo]:
    async for m in super()._get_info(extended):
      yield m

    manif = self._get_xapk_manifest()
    yield {
      'xapk vers': manif['xapk_version'],
      'xapk slices': '{} ({})'.format(len(manif['split_apks']), ', '.join([x['id'] for x in manif['split_apks']])),
    }

  def _get_xapk_manifest(self) -> XAPKManifest:
    from zipfile import ZipFile
    from json import loads
    with ZipFile(self.target) as zf:
      manif: XAPKManifest = loads(zf.read('manifest.json'))
      assert str(manif['xapk_version']) == '2'
      return manif
