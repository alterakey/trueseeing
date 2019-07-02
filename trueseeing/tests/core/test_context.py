import unittest

from trueseeing.core.context import Context


class TestContext(unittest.TestCase):
    def test_get_min_sdk_version(self):
        context = Context('../libs/Android-InsecureBankv2/InsecureBankv2.apk')
        self.assertEqual(context.get_min_sdk_version(), 15)


if __name__ == '__main__':
    unittest.main()
