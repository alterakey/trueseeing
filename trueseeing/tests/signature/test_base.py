import unittest

from trueseeing.signature.base import SignatureDiscoverer, SignatureClasses


class TestSignatureDiscoverer(unittest.TestCase):
  def setUp(self):
    self.discover = SignatureDiscoverer()
    self.classes = SignatureClasses()

  def test_discovered(self):
    self.assertEqual(['fingerprint', 'manifest', 'security', 'battery', 'crypto', 'denial', 'privacy'],
                     self.discover.discovered())

  def test_extracted(self):
    for i in self.classes.extracted():
      print(i)

if __name__ == '__main__':
  unittest.main()
