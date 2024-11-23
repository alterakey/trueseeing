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
    from gzip import decompress
    from base64 import b64decode
    return decompress(b64decode('''
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
W5tc/+ytXbtu39/9Tqe8fh08b+v8fvnZD7ztK7cvqvX3y+W7/ujTb/bzWAtk+v5T+vo5yOv963Jwpx0e
bx/nnavtXEtsDqltX/Wl/nGX+sht6bv5/FnWbpeg7vJ8vn/vlV19i2/tad9T5+o/wtfd3mw+Ru8vf4Wy
f+bv8/te7s/VZ3W2n/Zy5Mf4cX7btciHk/3aN3k94/79UuPOmuvn4/xzaMp1uH+el5/H177z6xrP3z/7
Um91fH59Nefn+77n2xwf52OX0NvH1y+9fJ0/2186v+0zDxzdvuyhqyr2Y5vva8mPHZL0qNrfDIL65q75
/2Tf2/Ohqsp/1aeqmk5/C+yt/mrWv/3t+GWPY1e2ulTNn4z/sa/uPn/+mdpu/Vc3/xms+mmrOVR/sv3Z
fh2sJ1ufLP3r7k/efjWvJvxmXZzf0Yl3HJGjxL+72j3n3+w8XNo/C8tvTf9nYfl5+TPp871uTvbI+uf3
z/nYGzq3vB+iPj7z/byfzMRCPuyr+c24H3dwh0x87hThy07c16/2L5VOJ/ycPb/dt8vB5/BWP973lQaW
3X63u02aOcX2l9oPdq7yz9fXvqi5q9Kp2fvNKW2HIbn/XLfqWPe9vtnzPB6Zp923EPv7+vO58zWGdfn+
3reffv6KOzHDx8f73iZ/nqqPY625vj32vWV/f/953rf9cJdpmd/3iwFfYNTLQqU3Phf/qXP1/8vxE/6Z
H0dFf1/WnVru35/HtfN4j98fbvhu++Wj0ZPNUZjeTzt7Hh0CU/+Sw7HAZ3//uBxDPG/1xQ5v/eYOe6uC
ZnizH86ddsZtP4j8fSfbGN7959cuYRvydLHjuJ/oq43nYqGI9wmInjiPz+1lNlvrP+RmCeSAOJUEpJu8
k6fZnNlCgwOt58QtdBZwCz2NjH70k4pLt2Wz0ell+fDqE4i9vvRf9YVrRCLkfI3mpbj+tbgSXL8e5n8B
fez0vAwoAAA=
    ''')).decode('ascii')

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
