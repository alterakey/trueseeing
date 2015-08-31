import unittest
from hypothesis import given
from hypothesis.strategies import text

from trueseeing import shell

class ShellTest(unittest.TestCase):
  @given(text(), text())
  def test_invoke(self, name, fn):
    self.assertTrue(shell.shell([name, fn]) in [1, 2])
