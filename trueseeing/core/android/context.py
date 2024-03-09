from __future__ import annotations
from typing import TYPE_CHECKING

import lxml.etree as ET
import os
import re
import shutil
from functools import cache

from pubsub import pub

from trueseeing.core.ui import ui
from trueseeing.core.env import get_cache_dir, get_cache_dir_v0, get_cache_dir_v1
from trueseeing.core.context import Context

if TYPE_CHECKING:
  from typing import List, Any, Iterable, Tuple, Optional, ClassVar, Set, AsyncIterator
  from trueseeing.core.context import ContextType, ContextInfo
  from trueseeing.core.android.store import APKStore

class APKContext(Context):
  _store: Optional[APKStore] = None
  _type: ClassVar[Set[ContextType]] = {'apk', 'file'}

  def _workdir_of(self) -> str:
    fp = self.fingerprint_of()

    path = self._get_workdir_v2(fp)
    if os.path.isdir(path):
      return path
    else:
      paths = dict(v0=self._get_workdir_v0(fp), v1=self._get_workdir_v1(fp))
      for vers,trypath in paths.items():
        if os.path.isdir(trypath):
          ui.warn(f'cpntext uses old path ({vers}), consider moving it to {path}')
          return trypath
      else:
        return path

  def _get_workdir_v2(self, fp: str) -> str:
    return os.path.join(get_cache_dir(), fp)

  def _get_workdir_v1(self, fp: str) -> str:
    return os.path.join(get_cache_dir_v1(self._path), f'.trueseeing2-{fp}')

  def _get_workdir_v0(self, fp: str) -> str:
    return os.path.join(get_cache_dir_v0(), fp)

  def create(self, exist_ok: bool = False) -> None:
    super().create(exist_ok=exist_ok)
    self._copy_target()

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
    from hashlib import sha256
    with open(self._path, 'rb') as f:
      return sha256(f.read()).hexdigest()

  async def _recheck_schema(self) -> None:
    from trueseeing.core.android.store import APKStore
    APKStore.require_valid_schema_on(self.wd)

  async def _analyze(self, level: int) -> None:
    from trueseeing.core.android.asm import APKDisassembler
    from trueseeing.core.android.analysis.smali import SmaliAnalyzer
    pub.sendMessage('progress.core.context.disasm.begin')
    disasm = APKDisassembler(self)
    await disasm.disassemble(level)
    pub.sendMessage('progress.core.context.disasm.done')

    if level > 3:
      SmaliAnalyzer(self.store()).analyze()

  def get_package_name(self) -> str:
    return self.parsed_manifest().attrib['package']  # type: ignore[no-any-return]

  async def _get_info(self) -> AsyncIterator[ContextInfo]:
    async for m in super()._get_info():
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
          for nr, in c.execute('select count(1) from classes_extends_name where extends_name regexp :pat', dict(pat='^Landroid.*Fragment(Compat)?;$')):
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
          for nr, in c.execute('select count(1) from ops where idx=0'):
            yield dict(ops='{}'.format(nr))
          for nr, in c.execute('select count(1) from class_class_name'):
            yield dict(classes='{}'.format(nr))
          for nr, in c.execute('select count(1) from method_method_name'):
            yield dict(methods='{}'.format(nr))

  def _copy_target(self) -> None:
    if not os.path.exists(os.path.join(self.wd, 'target.apk')):
      shutil.copyfile(self._path, os.path.join(self.wd, 'target.apk'))

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
