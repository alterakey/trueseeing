from __future__ import annotations
from typing import TYPE_CHECKING

import functools
import lxml.etree as ET
import os
import re
import shutil

from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import List, Any, Iterable, Tuple, Optional
  from trueseeing.core.store import Store

class Context:
  wd: str
  excludes: List[str]
  _apk: str
  _store: Optional[Store] = None

  def __init__(self, apk: str, excludes: List[str]) -> None:
    self._apk = apk
    self.wd = self._workdir_of()
    self.excludes = excludes

  def _workdir_of(self) -> str:
    hashed = self.fingerprint_of()
    if os.environ.get('TS2_CACHEDIR'):
      dirname = os.path.join(os.environ['TS2_CACHEDIR'], hashed)
    else:
      dirname = os.path.join(os.path.dirname(self._apk), f'.trueseeing2-{hashed}')
    return dirname

  def store(self) -> Store:
    if self._store is None:
      assert self.wd is not None
      from trueseeing.core.store import Store
      self._store = Store(self.wd)
    return self._store

  def fingerprint_of(self) -> str:
    from hashlib import sha256
    with open(self._apk, 'rb') as f:
      return sha256(f.read()).hexdigest()

  def remove(self) -> None:
    if os.path.exists(self.wd):
      shutil.rmtree(self.wd)
    self._store = None

  def create(self, exist_ok: bool = False) -> None:
    os.makedirs(self.wd, mode=0o700, exist_ok=exist_ok)
    self._copy_target()

  def _get_analysis_flag_name(self, level: int) -> str:
    return f'.done{level}' if level < 3 else '.done'

  def get_analysis_level(self) -> int:
    for level in range(3, 0, -1):
      if os.path.exists(os.path.join(self.wd, self._get_analysis_flag_name(level))):
        return level
    return 0

  async def analyze(self, level: int = 3, skip_resources: bool = False) -> None:
    if self.get_analysis_level() >= level:
      ui.debug('analyzed once')
    else:
      flagfn = self._get_analysis_flag_name(level)
      from trueseeing.core.asm import APKDisassembler
      from trueseeing.core.code.parse import SmaliAnalyzer
      if os.path.exists(self.wd):
        ui.info('analyze: removing leftover')
        self.remove()

      if level > 0:
        ui.info('analyze: disassembling... ', nl=False)
        self.create()
        disasm = APKDisassembler(self, skip_resources)
        disasm.disassemble(level)
        ui.info('analyze: disassembling... done.', ow=True)

        if level > 2:
          SmaliAnalyzer(self.store()).analyze()

      with open(os.path.join(self.wd, flagfn), 'w'):
        pass

    from trueseeing.core.api import Extension
    Extension.get().patch_context(self)

  def _copy_target(self) -> None:
    if not os.path.exists(os.path.join(self.wd, 'target.apk')):
      shutil.copyfile(self._apk, os.path.join(self.wd, 'target.apk'))

  def parsed_manifest(self, patched: bool = False) -> Any:
    return self.store().query().file_get_xml('AndroidManifest.xml', patched=patched)

  def manifest_as_xml(self, manifest: Any) -> bytes:
    assert manifest is not None
    return ET.tostring(manifest) # type: ignore[no-any-return]

  def _parsed_apktool_yml(self) -> Any:
    # FIXME: using ruamel.yaml?
    import yaml
    o = self.store().query().file_get('apktool.yml')
    if o is not None:
      return yaml.safe_load(re.sub(r'!!brut\.androlib\..*', '', o.decode('utf-8')))

  def get_target_sdk_version(self) -> int:
    manif = self.parsed_manifest()
    try:
      e = manif.xpath('.//uses-sdk')[0]
      return int(e.attrib.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '1'))
    except IndexError:
      return int(self._parsed_apktool_yml()['sdkInfo']['targetSdkVersion'])

  # FIXME: Handle invalid values
  def get_min_sdk_version(self) -> int:
    manif = self.parsed_manifest()
    try:
      e = manif.xpath('.//uses-sdk')[0]
      return int(e.attrib.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '1'))
    except IndexError:
      return int(self._parsed_apktool_yml()['sdkInfo']['minSdkVersion'])

  @functools.lru_cache(maxsize=1)
  def disassembled_classes(self) -> List[str]:
    return list(self.store().query().file_find('smali%.smali'))

  @functools.lru_cache(maxsize=1)
  def disassembled_resources(self) -> List[str]:
    return list(self.store().query().file_find('%/res/%.xml'))

  @functools.lru_cache(maxsize=1)
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

  @functools.lru_cache(maxsize=1)
  def _string_resource_files(self) -> List[str]:
    return list(self.store().query().file_find('%/res/values/%strings%'))

  def string_resources(self) -> Iterable[Tuple[str, str]]:
    for _, o in self.store().query().file_enum('%/res/values/%strings%'):
      yield from ((c.attrib['name'], c.text) for c in ET.fromstring(o, parser=ET.XMLParser(recover=True)).xpath('//resources/string') if c.text)

  @functools.lru_cache(maxsize=1)
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
