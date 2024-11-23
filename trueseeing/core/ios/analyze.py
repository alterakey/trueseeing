from __future__ import annotations
from typing import TYPE_CHECKING
import os
import re

if TYPE_CHECKING:
    from typing import Iterable, Any, Iterator, Mapping, Tuple

def analyze_api(path: str) -> Iterator[Mapping[str, Any]]:
    def walker(path: str) -> Iterator[Tuple[str, bytes]]:
        for dirpath, _, filenames in os.walk(path):
            for fn in filenames:
                target = os.path.join(dirpath, fn)
                with open(target, 'rb') as f:
                    yield target, f.read()

    return analyze_api_in(walker(path))

def analyze_api_in(gen: Iterable[Tuple[str, bytes]]) -> Iterator[Mapping[str, Any]]:
    # XXX: focusing on oneline
    pats = rb'^([_.].*?:[0-9a-f]{8}) +?[0-9a-f]+ +?b[a-z]* +(.*?);(\[[A-Za-z]+ .*?\]|undefined _.*)$'
    blacklist = '|'.join([
        ' _objc_',
        ' _swift_',
        ' _OUTLINED_FUNCTION_[0-9]+',
        ' __cxa_',
        ' __swift_',
        ' __release_weak',
        ' ___cxa_',
        ' ___swift_',
        ' ___stack_chk_fail',
        ' ___chkstk_darwin',
    ])

    for fn, s in gen:
      for m in re.finditer(pats, s, flags=re.MULTILINE):
        origin = m.group(1).decode('latin1').strip('"').replace(':','+')
        target = m.group(2).decode('latin1').strip('"')
        call = m.group(3).decode('latin1').strip('"')
        if not re.search(blacklist, call):
          if call.startswith('['):
            lang = 'objc'
          elif call.startswith('undefined _$'):
            lang = 'swift'
          elif call.startswith('undefined __Z'):
            lang = 'cpp'
          else:
            lang = 'c'

          if 'EXTERNAL' in target:
            yield dict(fn=fn, origin=origin, typ='API', lang=lang, call=call)
          else:
            yield dict(fn=fn, origin=origin, typ='private', lang=lang, call=call)

def analyze_lib_needs_in(gen: Iterable[Tuple[str, bytes]]) -> Iterator[Mapping[str, Any]]:
    pats = rb"(@rpath)?/[0-9A-za-z/.]+(\.framework/[0-9A-za-z/.]+|.dylib)"

    seen = set()
    for n, s in gen:
      for m in re.finditer(pats, s[:1048576]):
          fnlike = m.group(0).decode('latin1').strip('"')
          if fnlike not in seen:
              seen.add(fnlike)
              yield dict(fn=n, v=fnlike)

def get_origin(n: str, l: bytes) -> Mapping[str, Any]:
    pat = rb'(_.*?:[0-9a-f]{8}(?: |[0-9a-f]))[0-9a-f]+? +[a-z]+ '
    m = re.match(pat, l)
    if m:
        origin = m.group(1).decode('latin1').strip('"')
        sect, offs = origin.split(':')
        return dict(fn=n, sect=sect, offs=int(offs, 16))
    else:
        raise ValueError()
