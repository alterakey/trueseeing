import re
import tempfile
import os
import lxml.etree as ET
import shutil
import pkg_resources

import trueseeing.smali

class NaiveContext:
  def __init__(self):
    self.notes = []
    self.apk = None
    self.wd = None
    self.state = {}

  def analyze(self, apk):
    if self.wd is None:
      self.apk = apk
      self.wd = tempfile.mkdtemp()
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
      self.state['ts2.context.analyzed_classes'] = trueseeing.smali.P.parsed('\n'.join(open(fn, 'r').read() for fn in self.disassembled_classes())).global_.classes
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

  def __enter__(self):
    return self

  def __exit__(self, *exc_details):
    shutil.rmtree(self.wd)

class TestContext(NaiveContext):
  def analyze(self, apk):
    if self.wd is None:
      self.apk = apk
      self.wd = '/var/folders/zx/4htjs7cn75dfd5r6kcqlvmhh0000gp/T/tmpec0f0i2o'
    else:
      return super().analyze(apk)

  def __exit__(self, *exc_details):
    pass
    #import pickle
    #with open('ts2-state', 'wb') as f:
    #  pickle.dump(self.state, f)

Context = TestContext
  
def warning_on(name, row, col, desc, opt):
  return dict(name=name, row=row, col=col, severity='warning', desc=desc, opt=opt)

