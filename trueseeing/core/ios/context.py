from __future__ import annotations
from typing import TYPE_CHECKING

import os
import os.path

from pubsub import pub

from trueseeing.core.context import Context, Fingerprint
from trueseeing.core.env import get_cache_dir
from trueseeing.core.ui import ui
from trueseeing.core.ios.store import IPAStore

if TYPE_CHECKING:
  from typing import List, Optional, Final, Set, TypedDict, Iterator, Any, Mapping
  from trueseeing.core.context import ContextType
  from trueseeing.core.db import FileEntry
  from trueseeing.core.ios.db import IPAQuery

  class Call(TypedDict):
    path: str
    sect: str
    offs: int
    priv: bool
    swift: bool
    objc: bool
    cpp: bool
    target: str

class IPAContext(Context):
  wd: str
  excludes: List[str]
  _path: str
  _store: Optional['IPAStore'] = None
  _type: Final[Set[ContextType]] = {'ipa', 'file'}
  _fp = Fingerprint()

  def invalidate(self) -> None:
    super().invalidate()
    self._fp.get.cache_clear()

  def _get_type(self) -> Set[ContextType]:
    return self._type

  def _get_workdir(self) -> str:
    return os.path.join(get_cache_dir(), 'ts2-ios-{}'.format(self._get_fingerprint()))

  def _get_size(self) -> Optional[int]:
    return os.stat(self._path).st_size

  def _get_fingerprint(self) -> str:
    return self._fp.get(self._path)

  async def _recheck_schema(self) -> None:
    pass

  def store(self) -> 'IPAStore':
    if self._store is None:
      self._store = IPAStore(self.wd)
    return self._store

  async def _analyze(self, level: int) -> None:
    q: IPAQuery
    if level > 0:
      import plistlib
      with self.store().query().scoped() as q:
        from zipfile import ZipFile
        with ZipFile(self._path, 'r') as zf:
          def _decode(n: str, b: bytes) -> FileEntry:
            if not n.endswith('Info,plist'):
              return dict(path=n, blob=b, z=True)
            else:
              return dict(path=n, blob=plistlib.dumps(plistlib.loads(b)), z=True)
          q.file_put_batch(_decode(i.filename, zf.read(i)) for i in zf.infolist() if not i.is_dir())

    if level > 2:
      tarpath = os.path.join(os.path.dirname(self._path), 'disasm.tar.gz')
      if not os.path.exists(tarpath):
        ui.fatal(f'prepare {tarpath}')
      with self.store().query().scoped() as q:
        pub.sendMessage('progress.core.analysis.nat.begin')
        import tarfile
        with tarfile.open(tarpath) as tf:
          q.file_put_batch(dict(path=f'disasm/{i.name}', blob=tf.extractfile(i).read(), z=True) for i in tf.getmembers() if (i.isreg() or i.islnk())) # type:ignore[union-attr]

        if level > 3:
          pub.sendMessage('progress.core.analysis.nat.analyzing')
          from trueseeing.core.ios.analyze import analyze_api_in

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
                swift=(lang == 'swift'),
                objc=(lang == 'objc'),
                cpp=(lang == 'cpp'),
                target=e['call']
              )

          q.call_add_batch(_as_call(analyze_api_in(q.file_enum('disasm/%'))))
          pub.sendMessage('progress.core.analysis.nat.summary', calls=q.call_count())
