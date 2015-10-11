# * Fingerprinting libraries
# * Fingerprinting obfuscators

import itertools
import os
import re
from trueseeing.context import warning_on

def package_name_of(path):
  return os.path.dirname(path).replace('/', '.')

def class_name_of(path):
  return path.replace('.smali', '').replace('/', '.')

def shared_package_of(c1, c2):
  o = []
  for a,b in zip(c1.split('.'), c2.split('.')):
    if a == b:
      o.append(a)
    else:
      return o

def is_kind_of(c1, c2):
  return True if shared_package_of(c1, c2) else False

def detect_library(context):
  package = context.parsed_manifest().getroot().xpath('/manifest/@package', namespaces=dict(android='http://schemas.android.com/apk/res/android'))[0]

  packages = dict()
  for fn in (context.source_name_of_disassembled_class(r) for r in context.disassembled_classes()):
    try:
      packages[package_name_of(fn)].append(fn)
    except KeyError:
      packages[package_name_of(fn)] = [fn]
  packages = {k:v for k,v in packages.items() if not is_kind_of(k, package) and re.search(r'\.[a-zA-Z0-9]{4,}(?:\.|$)', k)}

  return [warning_on(name=context.apk, row=1, col=0, desc='detected library: %s (score: %d)' % (p, len(packages[p])), opt='-Wdetect-library') for p in sorted(packages.keys())]

def detect_obfuscators(context):
  return detect_obfuscator_proguard(context)

def detect_obfuscator_proguard(context):
  for c in (class_name_of(context.source_name_of_disassembled_class(r)) for r in context.disassembled_classes()):
    if re.search(r'(?:^|\.)[A-Za-z]\.[A-Za-z]\.[A-Za-z]', c):
      return [warning_on(name=context.apk, row=1, col=0, desc='detected obfuscator: ProGuard', opt='-Wdetect-obfuscator')]
  else:
    return []
