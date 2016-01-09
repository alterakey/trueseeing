import re
import tempfile
import os
import lxml.etree as ET
import shutil
import pkg_resources
import hashlib

import trueseeing.code.parse

class Context:
  def __init__(self):
    self.notes = []
    self.apk = None
    self.wd = None
    self.state = {}

  def workdir_of(self, apk):
    with open(apk, 'rb') as f:
      hashed = hashlib.sha256(f.read()).hexdigest()
      dirname = os.path.join(os.environ['HOME'], '.trueseeing2', hashed[:2], hashed[2:4], hashed[4:])
      return dirname
    
  def analyze(self, apk):
    if self.wd is None:
      self.apk = apk      
      self.wd = self.workdir_of(apk)
      try:
        os.makedirs(self.wd, mode=0o700)
      except OSError:
        pass
      else:
        # XXX insecure
        os.system("java -jar %(apktool)s d -fo %(wd)s %(apk)s" % dict(apktool=pkg_resources.resource_filename(__name__, os.path.join('libs', 'apktool.jar')), wd=self.wd, apk=self.apk))
    else:
      raise ValueError('analyzed once')

  def parsed_manifest(self):
    with open(os.path.join(self.wd, 'AndroidManifest.xml'), 'r') as f:
      return ET.parse(f)

  def disassembled_classes(self):
    try:
      return self.state['ts2.context.disassembled_classes']
    except KeyError:
      self.state['ts2.context.disassembled_classes'] = []
      for root, dirs, files in os.walk(os.path.join(self.wd, 'smali')):
        self.state['ts2.context.disassembled_classes'].extend(os.path.join(root, f) for f in files if f.endswith('.smali'))
      return self.disassembled_classes()

  def analyzed_classes(self):
    try:
      return self.state['ts2.context.analyzed_classes']
    except KeyError:
      self.state['ts2.context.analyzed_classes'] = trueseeing.code.parse.P.parsed('\n'.join(open(fn, 'r').read() for fn in self.disassembled_classes())).global_.classes
      return self.analyzed_classes()

  def disassembled_resources(self):
    try:
      return self.state['ts2.context.disassembled_resources']
    except KeyError:
      self.state['ts2.context.disassembled_resources'] = []
      for root, dirs, files in os.walk(os.path.join(self.wd, 'res')):
        self.state['ts2.context.disassembled_resources'].extend(os.path.join(root, f) for f in files if f.endswith('.xml'))
      return self.disassembled_resources()

  def source_name_of_disassembled_class(self, fn):
    return os.path.relpath(fn, os.path.join(self.wd, 'smali'))

  def dalvik_type_of_disassembled_class(self, fn):
    return 'L%s;' % (self.source_name_of_disassembled_class(fn).replace('.smali', ''))

  def source_name_of_disassembled_resource(self, fn):
    return os.path.relpath(fn, os.path.join(self.wd, 'res'))

  def class_name_of_dalvik_class_type(self, dc):
    return re.sub(r'^L|;$', '', dc).replace('/', '.')

  def permissions_declared(self):
    yield from self.parsed_manifest().getroot().xpath('//uses-permission/@android:name', namespaces=dict(android='http://schemas.android.com/apk/res/android'))

  def string_resource_files(self):
    try:
      return self.state['ts2.context.string_resource_files']
    except KeyError:
      self.state['ts2.context.string_resource_files'] = []
      for root, dirs, files in os.walk(os.path.join(self.wd, 'res', 'values')):
        self.state['ts2.context.string_resource_files'].extend(os.path.join(root, f) for f in files if 'strings' in f)
      return self.string_resource_files()

  def string_resources(self):
    for fn in self.string_resource_files():
      with open(fn, 'r') as f:
        yield from ((c.attrib['name'], c.text) for c in ET.parse(f).getroot().xpath('//resources/string') if c.text)
      
  def __enter__(self):
    return self

  def __exit__(self, *exc_details):
    pass
  
def warning_on(name, row, col, desc, opt):
  return dict(name=name, row=row, col=col, severity='warning', desc=desc, opt=opt)

