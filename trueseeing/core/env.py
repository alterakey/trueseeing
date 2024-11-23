from __future__ import annotations
from typing import TYPE_CHECKING

from functools import cache
import os

if TYPE_CHECKING:
  from typing import Optional

@cache
def get_home_dir() -> str:
  return os.environ.get('TS2_HOME', os.path.join(os.environ['HOME'], '.trueseeing2'))

@cache
def get_rc_path() -> str:
  return os.path.join(get_home_dir(), 'rc')

@cache
def get_cache_dir() -> str:
  return get_cache_dir_v2()

@cache
def get_cache_dir_v0() -> str:
  return get_home_dir()

@cache
def get_cache_dir_v1(target: str) -> str:
  return os.environ.get('TS2_CACHEDIR', os.path.dirname(target))

@cache
def get_cache_dir_v2() -> str:
  return os.environ.get('TS2_CACHEDIR', os.path.join(get_home_dir(), 'cache'))

@cache
def get_adb_host() -> Optional[str]:
  return os.environ.get('TS2_ADB_HOST', ('tcp:host.docker.internal:5037' if is_in_container() else None))

@cache
def is_in_container() -> bool:
  return 'TS2_IN_DOCKER' in os.environ

@cache
def get_shell() -> str:
  return os.environ.get('SHELL', '/bin/sh')

@cache
def get_extension_dir() -> str:
  return os.environ.get('TS2_EXTDIR', os.path.join(get_home_dir(), 'extensions'))

@cache
def get_extension_dir_v0() -> str:
  return get_home_dir()

@cache
def get_extension_package_prefix() -> str:
  return 'trueseeing_ext0_'

@cache
def get_device_frida_dir(package_name: str) -> str:
  return '/data/local/tmp/ts2/{pkg}/frida'.format(pkg=package_name)

@cache
def get_swift_demangler_url() -> str:
  return os.environ.get('TS2_SWIFT_DEMANGLER_URL', 'http://127.0.0.1:8000')

@cache
def get_cache_schema_id() -> int:
  return 0x54f6d672  # FIXME: remember to randomize this whenever incompatible changes occur on cache file structure, or DB schema
