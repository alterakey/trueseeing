from __future__ import annotations
from typing import TYPE_CHECKING

from functools import lru_cache
import os

if TYPE_CHECKING:
  from typing import Optional

@lru_cache(maxsize=None)
def get_home_dir() -> str:
  return os.environ.get('TS2_HOME', os.path.join(os.environ['HOME'], '.trueseeing2'))

@lru_cache(maxsize=None)
def get_cache_dir(target: str) -> str:
  return os.environ.get('TS2_CACHEDIR', os.path.dirname(target))

@lru_cache(maxsize=None)
def is_cache_dir_static() -> bool:
  return 'TS2_CACHEDIR' in os.environ

@lru_cache(maxsize=None)
def get_adb_host() -> Optional[str]:
  return os.environ.get('TS2_ADB_HOST', ('tcp:host.docker.internal:5037' if is_in_container() else None))

@lru_cache(maxsize=None)
def is_in_container() -> bool:
  return 'TS2_IN_DOCKER' in os.environ
