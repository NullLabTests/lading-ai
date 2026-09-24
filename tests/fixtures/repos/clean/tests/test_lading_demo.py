import unittest

from clean_repo import greet


class GreetTest(unittest.TestCase):
    def test_greet(self):
        self.assertEqual(greet("dock"), "hello dock")


if __name__ == "__main__":
    unittest.main()