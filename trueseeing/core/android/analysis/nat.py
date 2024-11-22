from __future__ import annotations
from typing import TYPE_CHECKING
from functools import cache
import os
import re

if TYPE_CHECKING:
    from typing import Iterable, Dict, Any, Iterator, Mapping, Tuple

def _analyzed(x: str, tlds: re.Pattern[str]) -> Iterable[Dict[str, Any]]:
    if '://' in x:
        yield dict(type_='URL', value=re.findall(r'\S+://\S+', x))
    elif re.search(r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+', x):
        yield dict(type_='path component', value=re.findall(r'^/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+', x))
    elif re.search(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?$', x):
        m = re.search(r'^([^:/]+)', x)
        if m:
            hostlike = m.group(1)
            components = hostlike.split('.')
            if len(components) == 4 and all(re.match(r'^\d+$', c) for c in components) and all(int(c) < 256 for c in components):
                yield dict(type_='possible IPv4 address', value=[hostlike])
            elif tlds.search(components[-1]):
                if not re.search(r'^android\.(intent|media)\.|^os\.name$|^java\.vm\.name|^[A-Z]+.*\.(java|EC|name|secure)$', hostlike):
                    yield dict(type_='possible FQDN', value=[hostlike])

@cache
def _pat(c: str) -> re.Pattern[str]:
    from io import StringIO
    f = StringIO(c)
    return re.compile('^(?:{})$'.format('|'.join(re.escape(l.strip()) for l in f if l and not l.startswith('#'))), flags=re.IGNORECASE)

@cache
def _tlds() -> str:
    from importlib.resources import files
    with (files('trueseeing')/'libs'/'public_suffix_list.dat').open('r', encoding='utf-8') as f:
      return f.read()

def analyze_url(path: str) -> Iterator[Mapping[str, Any]]:
    def walker(path: str) -> Iterator[Tuple[str, bytes]]:
        for dirpath, _, filenames in os.walk(path):
            for fn in filenames:
                target = os.path.join(dirpath, fn)
                with open(target, 'rb') as f:
                    yield target, f.read()

    return analyze_url_in(walker(path))

def analyze_url_in(gen: Iterable[Tuple[str, bytes]]) -> Iterator[Mapping[str, Any]]:
    tlds = _pat(_tlds())

    pats = rb'|'.join([
        b"([a-z0-9A-Z]+://[^\\\"<>()' \\t\\n\\v\\r\\x00-\\x1f\\x80-\\xff]+)",
        rb'"/[{}$%a-zA-Z0-9_-]+(/[{}$%a-zA-Z0-9_-]+)+',
        rb'"[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?"',
    ])

    seen = set()
    for n, s in gen:
      for m in re.finditer(pats, s):
          urllike = m.group(0).decode('latin1').strip('"')
          if urllike not in seen:
              seen.add(urllike)
              for d in _analyzed(urllike, tlds):
                  for v in d['value']:
                      yield dict(fn=n, typ=d['type_'], v=v)

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

def get_origin(n: str, l: bytes) -> Mapping[str, Any]:
    pat = rb'(_.*?:[0-9a-f]{8}) +?[0-9a-f]+? +[a-z]+ '
    m = re.match(pat, l)
    if m:
        origin = m.group(1).decode('latin1').strip('"')
        sect, offs = origin.split(':')
        return dict(fn=n, sect=sect, offs=int(offs, 16))
    else:
        raise ValueError()
