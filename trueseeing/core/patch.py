import logging
import os
import shutil
import tempfile

import pkg_resources

from trueseeing.core.sign import SigningKey
from trueseeing.core.context import Context

log = logging.getLogger(__name__)

class Patch:
  def apply(self, context):
    pass

class Patcher:
  def __init__(self, apk, out):
    self.apk = os.path.realpath(apk)
    self.out = out

  def apply(self, patch):
    return self.apply_multi([patch])

  def apply_multi(self, patches):
    with Context(self.apk) as context:
      context.analyze()
      log.info("%s -> %s" % (self.apk, context.wd))
      for p in patches:
          p.apply(context)

      # XXX
      sigfile = 'CERT'

      # XXX insecure
      with tempfile.TemporaryDirectory() as d:
        os.system("(mkdir -p %(root)s/)" % dict(root=d, apk=self.apk))
        os.system("(cd %(wd)s && java -jar %(apktool)s b -o %(root)s/patched.apk .)" % dict(root=d, apktool=pkg_resources.resource_filename(__name__, os.path.join('..', 'libs', 'apktool.jar')), wd=context.wd))
        os.system("(cd %(root)s && jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore %(keystore)s -storepass android -keypass android -sigfile %(sigfile)s patched.apk androiddebugkey)" % dict(root=d, keystore=SigningKey().key(), sigfile=sigfile))
        shutil.copyfile(os.path.join(d, 'patched.apk'), self.out)