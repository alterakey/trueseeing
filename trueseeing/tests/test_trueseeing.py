import sys
import os
import unittest

import trueseeing.app.shell


class TestTrueseeing(unittest.TestCase):
  def test_trueseeing(self):
    os.chdir(os.path.dirname(__file__))
    sys.argv.append('libs/Android-InsecureBankv2/InsecureBankv2.apk')
    trueseeing.app.shell.shell()

    # TODO assert count of severity


if __name__ == '__main__':
    unittest.main()
