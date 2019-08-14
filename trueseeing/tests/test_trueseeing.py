import sys
import os
import unittest

from trueseeing.app.shell import Shell


class TestTrueseeing(unittest.TestCase):
  def test_trueseeing(self):
    os.chdir(os.path.dirname(__file__))
    sys.argv.append('libs/Android-InsecureBankv2/InsecureBankv2.apk')
    Shell().invoke()

    # TODO assert count of severity

  def test_exploit(self):
    os.chdir(os.path.dirname(__file__))
    sys.argv.append('--exploit-enable-backup')
    sys.argv.append('libs/Android-InsecureBankv2/InsecureBankv2.apk')
    Shell().invoke()


if __name__ == '__main__':
    unittest.main()
