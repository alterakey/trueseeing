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
def get_rc_path() -> str:
  return os.path.join(get_home_dir(), 'rc')

@lru_cache(maxsize=None)
def get_cache_dir() -> str:
  return get_cache_dir_v2()

@lru_cache(maxsize=None)
def get_cache_dir_v0() -> str:
  return get_home_dir()

@lru_cache(maxsize=None)
def get_cache_dir_v1(target: str) -> str:
  return os.environ.get('TS2_CACHEDIR', os.path.dirname(target))

@lru_cache(maxsize=None)
def get_cache_dir_v2() -> str:
  return os.environ.get('TS2_CACHEDIR', os.path.join(get_home_dir(), 'cache'))

@lru_cache(maxsize=None)
def get_adb_host() -> Optional[str]:
  return os.environ.get('TS2_ADB_HOST', ('tcp:host.docker.internal:5037' if is_in_container() else None))

@lru_cache(maxsize=None)
def is_in_container() -> bool:
  return 'TS2_IN_DOCKER' in os.environ

@lru_cache(maxsize=None)
def get_shell() -> str:
  return os.environ.get('SHELL', '/bin/sh')

@lru_cache(maxsize=None)
def get_extension_dir() -> str:
  return os.environ.get('TS2_EXTDIR', os.path.join(get_home_dir(), 'extensions'))

@lru_cache(maxsize=None)
def get_extension_dir_v0() -> str:
  return get_home_dir()

@lru_cache(maxsize=None)
def get_extension_package_prefix() -> str:
  return 'trueseeing_ext0_'
