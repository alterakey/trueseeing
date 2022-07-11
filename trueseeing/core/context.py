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

  def __init__(self, apk: str, excludes: List[str]) -> None:
    self._apk = apk
    self.wd = self._workdir_of()
    self.excludes = excludes

  def _workdir_of(self) -> str:
    hashed = self.fingerprint_of()
    dirname = os.path.join(os.path.dirname(self._apk), f'.trueseeing2-{hashed}')
    return dirname

  @functools.lru_cache(maxsize=None)
  def store(self) -> Store:
    assert self.wd is not None
    from trueseeing.core.store import Store
    return Store(self.wd)

  def fingerprint_of(self) -> str:
    from hashlib import sha256
    with open(self._apk, 'rb') as f:
      return sha256(f.read()).hexdigest()

  async def analyze(self, skip_resources: bool = False) -> None:
    if os.path.exists(os.path.join(self.wd, '.done')):
      ui.debug('analyzed once')
    else:
      from trueseeing.core.asm import APKDisassembler
      from trueseeing.core.code.parse import SmaliAnalyzer
      if os.path.exists(self.wd):
        ui.info('analyze: removing leftover')
        shutil.rmtree(self.wd)

      ui.info('\ranalyze: disassembling... ', nl=False)
      os.makedirs(self.wd, mode=0o700)
      self._copy_target()
      APKDisassembler(self, skip_resources).disassemble()
      ui.info('\ranalyze: disassembling... done.')

      SmaliAnalyzer(self.store()).analyze()

      with open(os.path.join(self.wd, '.done'), 'w'):
        pass

    from trueseeing.core.api import Extension
    Extension.get().patch_context(self)

  def _copy_target(self) -> None:
    if not os.path.exists(os.path.join(self.wd, 'target.apk')):
      shutil.copyfile(self._apk, os.path.join(self.wd, 'target.apk'))

  def parsed_manifest(self, patched: bool = False) -> Any:
    stmt0 = 'select blob from files where path=:path'
    stmt1 = 'select coalesce(B.blob, A.blob) as blob from files as A left join patches as B using (path) where path=:path'
    with self.store().db as db:
      for o, in db.execute(stmt1 if patched else stmt0, dict(path='AndroidManifest.xml')):
        return ET.fromstring(o, parser=ET.XMLParser(recover=True))

  def manifest_as_xml(self, manifest: Any) -> bytes:
    assert manifest is not None
    return ET.tostring(manifest) # type: ignore[no-any-return]

  def _parsed_apktool_yml(self) -> Any:
    # FIXME: using ruamel.yaml?
    import yaml
    with self.store().db as db:
      for o, in db.execute('select blob from files where path=:path', dict(path='apktool.yml')):
        return yaml.safe_load(re.sub(r'!!brut\.androlib\.meta\.MetaInfo', '', o.decode('utf-8')))

  # FIXME: Handle invalid values
  def get_min_sdk_version(self) -> int:
    return int(self._parsed_apktool_yml()['sdkInfo']['minSdkVersion'])

  @functools.lru_cache(maxsize=1)
  def disassembled_classes(self) -> List[str]:
    with self.store().db as db:
      return [f for f, in db.execute('select path from files where path like :path', dict(path='smali%.smali'))]

  @functools.lru_cache(maxsize=1)
  def disassembled_resources(self) -> List[str]:
    with self.store().db as db:
      return [f for f, in db.execute('select path from files where path like :path', dict(path='res/%.xml'))]

  @functools.lru_cache(maxsize=1)
  def disassembled_assets(self) -> List[str]:
    with self.store().db as db:
      return [f for f, in db.execute('select path from files where path like :path', dict(path='assets/%'))]

  def source_name_of_disassembled_class(self, fn: str) -> str:
    return os.path.join(*fn.split('/')[1:])

  def dalvik_type_of_disassembled_class(self, fn: str) -> str:
    return 'L{};'.format((self.source_name_of_disassembled_class(fn).replace('.smali', '')))

  def source_name_of_disassembled_resource(self, fn: str) -> str:
    return os.path.join(*fn.split('/')[1:])

  def class_name_of_dalvik_class_type(self, dc: str) -> str:
    return re.sub(r'^L|;$', '', dc).replace('/', '.')

  def permissions_declared(self) -> Iterable[Any]:
    yield from self.parsed_manifest().xpath('//uses-permission/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android'))

  @functools.lru_cache(maxsize=1)
  def _string_resource_files(self) -> List[str]:
    with self.store().db as db:
      return [f for f, in db.execute('select path from files where path like :path', dict(path='res/values/%strings%'))]

  def string_resources(self) -> Iterable[Tuple[str, str]]:
    with self.store().db as db:
      for o, in db.execute('select blob from files where path like :path', dict(path='res/values/%strings%')):
        yield from ((c.attrib['name'], c.text) for c in ET.fromstring(o, parser=ET.XMLParser(recover=True)).xpath('//resources/string') if c.text)

  @functools.lru_cache(maxsize=1)
  def _xml_resource_files(self) -> List[str]:
    with self.store().db as db:
      return [f for f, in db.execute('select path from files where path like :path', dict(path='res/xml/%.xml'))]

  def xml_resources(self) -> Iterable[Tuple[str, Any]]:
    with self.store().db as db:
      for fn, o in db.execute('select path, blob from files where path like :path', dict(path='res/xml/%.xml')):
        yield (fn, ET.fromstring(o, parser=ET.XMLParser(recover=True)))

  def is_qualname_excluded(self, qualname: Optional[str]) -> bool:
    if qualname is not None:
      return any([re.match(f'L{x}', qualname) for x in self.excludes])
    else:
      return False

  def __enter__(self) -> Context:
    return self

  def __exit__(self, *exc_details: Any) -> None:
    pass
