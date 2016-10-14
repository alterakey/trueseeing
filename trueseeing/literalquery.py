import os.path
import pkg_resources

class Store:
  def __init__(self, c):
    self.c = c

  def stage0(self):
    with open(pkg_resources.resource_filename(__name__, os.path.join('libs', 'store.0.sql')), 'r') as f:
      self.c.executescript(f.read())

  def stage1(self):
    with open(pkg_resources.resource_filename(__name__, os.path.join('libs', 'store.1.sql')), 'r') as f:
      self.c.executescript(f.read())
