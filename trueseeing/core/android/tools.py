from __future__ import annotations
from typing import TYPE_CHECKING

from contextlib import contextmanager

if TYPE_CHECKING:
  from pathlib import Path
  from typing import TypeVar, Iterator, TypedDict
  T = TypeVar('T')

  class Toolchain(TypedDict):
    apkeditor: Path
    apksigner: Path
    abe: Path

@contextmanager
def toolchains() -> Iterator[Toolchain]:
  from trueseeing.core.tools import require_in_path
  from importlib.resources import files, as_file
  require_in_path('java', 'java -version')
  libs = files('trueseeing')/'libs'/'android'
  with as_file(libs/'apkeditor.jar') as apkeditorpath:
    with as_file(libs/'apksigner.jar') as apksignerpath:
      with as_file(libs/'abe.jar') as abepath:
        yield dict(
          apkeditor=apkeditorpath,
          apksigner=apksignerpath,
          abe=abepath,
        )

def move_apk(src: str, dest: str) -> None:
  import shutil
  shutil.move(src, dest)
  try:
    shutil.move(src.replace('.apk', '.apk.idsig'), dest.replace('.apk', '.apk.idsig'))
  except OSError:
    pass
