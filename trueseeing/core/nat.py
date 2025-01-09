from __future__ import annotations
from typing import TYPE_CHECKING

import os
from contextlib import contextmanager

if TYPE_CHECKING:
  from typing import Iterator, Optional
  from tarfile import TarFile
  from trueseeing.core.db import FileEntry

class CodeArchiveReader:
  def __init__(self, fn: str) -> None:
    self.fn = fn

  def _resolve(self) -> Optional[str]:
    for ext in ['.zst', '.gz', '.bz2', '']:
      tarpath = os.path.join(os.path.dirname(self.fn), f'disasm.tar{ext}')
      if os.path.exists(tarpath):
        return tarpath
    return None

  @contextmanager
  def _open(self) -> Iterator[TarFile]:
    tarpath = self._resolve()
    if tarpath is None:
      from trueseeing.core.exc import CodeArchiveNotFoundError
      raise CodeArchiveNotFoundError()

    import tarfile
    if tarpath.endswith('.zst'):
      from pyzstd import open as zstdopen
      with zstdopen(tarpath, 'rb') as f:
        yield tarfile.open(tarpath, fileobj=f) # type:ignore[call-overload]
    else:
      yield tarfile.open(tarpath)

  def exists(self) -> bool:
    return self._resolve() is not None

  def read(self, prefix: Optional[str] = None) -> Iterator[FileEntry]:
    if prefix is None:
      prefix = ''
    with self._open() as tf:
      for i in tf:
        if i.isreg() or i.islnk():
          yield dict(path=f'{prefix}{i.name}', blob=tf.extractfile(i).read(), z=True) # type: ignore[union-attr]
