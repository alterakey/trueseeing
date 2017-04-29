import unittest
import io
from trueseeing.store import Store
from trueseeing.code.parse import SmaliAnalyzer
from trueseeing.flow import data
from trueseeing.code.model import Op

class DataFlowTest(unittest.TestCase):
    def test_000(self):
        s = Store('.')
        f = io.StringIO('''
.class public final LA;
.super Ljava/lang/Object;
.method public a()V

return-void

return-void

.end method
''')
        SmaliAnalyzer(s).analyze([f])
        for o in s.query().ops():
            print(o)
        for o in data.DataFlows.looking_behind_from(s, Op.of_id(12)):
            print(o)
        assert False
        with SmaliWorkBench().smali({'A', }) as wb:
            pass
