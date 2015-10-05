import os
import unittest
import random
from hypothesis import given
from hypothesis.strategies import text

import collections

from trueseeing import smali

class SmaliDBTest(unittest.TestCase):
  def test_000(self):
    with open(os.path.join(os.path.dirname(__file__), "fixture_0.smali"), "r") as f:
      clazz = smali.Smali().parsed(f.read())
      o = random.choice([co for co in smali.CodeFlows.invocations_in(clazz.ops)])
      print("[.] Tracing for: %s" % o)
      for c in smali.DataFlows.into(o):
        for m,c in smali.CodeFlows.callstacks_of(c).items():
          print('%s -> %s' % (m, c))
        #all_ops = [x for x in smali.CodeFlows.callstacks_of(c.method_)]
        #print(len(all_ops), all_ops)
    assert False
