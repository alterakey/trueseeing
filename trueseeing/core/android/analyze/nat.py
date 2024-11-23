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
    pats = rb'^([_.].*?:[0-9a-f]{8}) +?[0-9a-f]+ +?b[a-z]* +(.*?);([A-Za-z]+ .*)$'
    blacklist = '|'.join([
        r' (thunk_)?FUN_[0-9a-f]+',
        r' __cxa_',
        r' __stack_chk_fail',
        r' operator\.',
        r' ~',
    ])

    for fn, s in gen:
      for m in re.finditer(pats, s, flags=re.MULTILINE):
        origin = m.group(1).decode('latin1').strip('" ').replace(':','+')
        target = m.group(2).decode('latin1').strip('" ')
        call = m.group(3).decode('latin1').strip('" ')
        if not re.search(blacklist, call):
          if re.search(r'operator|::.*?::', call):
            lang = 'cpp'
          else:
            lang = 'c'

          if 'EXTERNAL' in target:
            yield dict(fn=fn, origin=origin, typ='API', lang=lang, call=call)
          else:
            yield dict(fn=fn, origin=origin, typ='private', lang=lang, call=call)
