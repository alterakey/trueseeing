# * Fingerprinting libraries
# * Fingerprinting obfuscators

import os
import re
from trueseeing.context import warning_on

def class_name_of(c):
  return os.path.dirname(c).replace('/', '.')

def detect_library(context):
  package = context.parsed_manifest().getroot().xpath('/manifest/@package', namespaces=dict(android='http://schemas.android.com/apk/res/android'))[0]
  classes = dict()
  for fn in (context.source_name_of_disassembled_class(r) for r in context.disassembled_classes()):
    try:
      classes[class_name_of(fn)].append(fn)
    except KeyError:
      classes[class_name_of(fn)] = [fn]
  classes = {k:v for k,v in classes.items() if not k.startswith(package) and re.search(r'\.[a-zA-Z0-9]{4,}(?:\.|$)', k)}

  return [warning_on(name=context.apk, row=1, col=0, desc='detected library: %s (score: %d)' % (c, len(classes[c])), opt='-Wdetect-library') for c in sorted(classes.keys())]

def detect_obfuscators(context):
  pass
