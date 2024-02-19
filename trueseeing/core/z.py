from __future__ import annotations
import zstandard as zstd

def zd(item: bytes) -> bytes:
  return zstd.ZstdDecompressor().decompress(item)

def ze(item: bytes) -> bytes:
  return zstd.ZstdCompressor(threads=-1).compress(item)
