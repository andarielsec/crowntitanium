import unittest
from ntru import *

df = 2
dg = 2
dr = 1
p = 3
q = 16
f = [-1, 1, 1]
g = [1, -1, 1, 0, -1]
N = 5
ntru = NTRU(df, dg, dr, p, q, N)
key = Keys(ntru, f, g)


class TestTextbook(unittest.TestCase):
    def test_163(self):
        expected = (key.f, key.g)
        actual = (f, g)
        self.assertEqual(expected, actual)

    def test_163b(self):
        expected = (key.Fp, key.Fq)
        actual = ([2, 0, 2, 2, 1], [10, 9, 3, 12, 15])
        self.assertEqual(expected, actual)

    def test_163c(self):
        expected = (key.h)
        actual = ([14, 11, 8, 3, 12])
        self.assertEqual(expected, actual)

    def test_163d(self):
        m = [-1, 0, 1, 1, 0]
        enc = Encrypt(key.h, ntru)
        expected = (key.h)
        actual = ([14, 11, 8, 3, 12])
        self.assertEqual(expected, actual)

    def test_163f(self):
        m = [-1, 0, 1, 1, 0]
        enc = Encrypt(key.h, ntru)
        e = enc.encrypt(m, r=[0, 1, 0, 0, -1])
        expected = [2, 2, -7, 5, -1]
        actual = e
        self.assertEqual(expected, actual)

    def test_163e(self):
        d = key.decrypt([2, 2, -7, 5, -1])
        expected = [-1, 0, 1, 1, 0]
        self.assertEqual(d, expected)


if __name__ == '__main__':
    unittest.main()
