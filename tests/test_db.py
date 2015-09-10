import os
import unittest
import random
from hypothesis import given
from hypothesis.strategies import text

from trueseeing import smali

class SmaliDBTest(unittest.TestCase):
  def test_000(self):
    with open(os.path.join(os.path.dirname(__file__), "fixture_0.smali"), "r") as f:
      clazz = smali.Smali().parsed(f.read())
      o = random.choice([co for co in clazz.ops if 'invoke' in co.v])
      print("[.] Tracing for: %s" % o)
      for c in smali.DataFlow.into_rec(o):
        print(c)
    assert True
