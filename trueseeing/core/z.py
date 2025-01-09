from __future__ import annotations
import pyzstd
from trueseeing.core.env import get_cpu_count

def zd(item: bytes) -> bytes:
  return pyzstd.decompress(item)

def ze(item: bytes) -> bytes:
  return pyzstd.compress(item, level_or_option={pyzstd.CParameter.nbWorkers: get_cpu_count()})
