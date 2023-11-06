"""
# Copyright 2020
# Jadon Schuler & Justin Baum
# NTRU Cryptosystem Implementation
# ntru.py
"""

from random import sample, shuffle, randint
import polynomials


class Lattice:
    """
    """
    def __init__(self, d1, d2, N):
        self.d1 = d1
        self.d2 = d2
        self.N = N

    def in_lattice(self, polynomial):
        """
        >>> Lattice(2,1,3).in_lattice([1,1,-1])
        True
        >>> Lattice(2,1,3).in_lattice([1,1,-1,-1])
        False
        """
        plus = 0
        negs = 0
        for i in polynomial:
            if i == 1:
                plus += 1
            elif i == -1:
                negs += 1
            elif i == 0:
                continue
            else:
                return False
        return plus == self.d1 and negs == self.d2

    def generate_polynomial(self):
        """
        d1 1's, d2 2's, and N - (d1 + d2) 0's
        >>> all([Lattice(30,31,100).in_lattice(Lattice(30,31,100).generate_polynomial()) for _ in range(10)])
        True
        """
        indices = sample(range(self.N), self.d1 + self.d2)
        shuffle(indices)
        polynomial = [0 for _ in range(self.N)]
        for i in indices[:self.d1]:
            polynomial[i] = 1
        for i in indices[self.d1:]:
            polynomial[i] = -1
        return polynomial


class Encrypt:
    """
    """
    def __init__(self, h, ntru):
        self.h = h
        self.ntru = ntru

    def encrypt(self, message, r=None):
        r = self.ntru.Lr.generate_polynomial() if not r else r
        r = polynomials.scalar_mult(r, self.ntru.p, self.ntru.q)
        e = polynomials.multiplication(r, self.h, self.ntru.q)
        e = polynomials.addition(e, message, self.ntru.q, self.ntru.N)
        e = polynomials.reduce_mod(e, self.ntru.q)
        return e


class Keys:
    """
    >>> message = [4,5,6,7,1,2,3,1]; ntru = NTRU(2,2,1,257,10007,8); key = Keys(ntru); encrypt=Encrypt(key.h, ntru); e = encrypt.encrypt(message); d = key.decrypt(e); d == polynomials.reduce_mod(message, 257)
    True
    >>> message = [-1, 0, 1, 1, 0]; ntru = NTRU(2,2,1,3,16,5); key = Keys(ntru); encrypt=Encrypt(key.h, ntru); e = encrypt.encrypt(message); d = key.decrypt(e); d == message;
    True
    >>> message = [-1, 0, 1, 1, 0]; ntru = NTRU(2,2,1,3,17,5); key = Keys(ntru); encrypt=Encrypt(key.h, ntru); e = encrypt.encrypt(message); d = key.decrypt(e); d == message;
    True
    """
    def __init__(self, ntru, f=None, g=None):
        self.ntru = ntru
        self.p = ntru.p
        self.q = ntru.q
        self.N = ntru.N
        flagf = f == None
        flagg = g == None
        self.f = f
        self.g = g
        # Guaranteeing a valid key
        while True:
            try:
                if flagf:
                    self.f = ntru.Lf.generate_polynomial()
                if flagg:
                    self.g = ntru.Lg.generate_polynomial()
                self.Fp = polynomials.getnullvector(self.f, self.p, self.N)
                self.Fq = polynomials.getnullvector(self.f, self.q, self.N)
                self.h = polynomials.multiplication(self.Fq, self.g, self.q,
                                                    self.N)
                if (polynomials.trim(self.h) == []):
                    continue
                if True:
                    # Check if key is working
                    flag = False
                    for _ in range(2):
                        message = [
                            randint(-self.p // 2, self.p // 2)
                            for _ in range(self.N)
                        ]
                        enc = Encrypt(self.h, self.ntru)
                        e = enc.encrypt(message)
                        d = self.decrypt(e)
                        if d != message:
                            flag = True
                            break
                    if flag: continue
                if (not polynomials.trim(
                        polynomials.multiplication(self.Fp, self.f, self.p))
                        == [1]):
                    continue
                if (not polynomials.trim(
                        polynomials.multiplication(self.Fq, self.f, self.q))
                        == [1]):
                    continue
                return
            except ZeroDivisionError:
                continue

    def __str__(self):
        return \
            """
            p = {}
            q = {}
            N = {}
            f = {}
            g = {}
            Fp = {}
            Fq = {}
            h = {}
            """.format(self.p, self.q, self.N, *list(map(polynomials.strpoly, [self.f, self.g, self.Fp, self.Fq, self.h])))

    def decrypt(self, cipher):
        aprime = polynomials.multiplication(self.f, cipher, self.q)
        a = polynomials.reduce_mod(aprime, self.q)
        m = polynomials.multiplication(self.Fp, a, self.p)
        return polynomials.reduce_mod(m, self.p)


class NTRU:
    """
    NTRU System
    """
    def __init__(self, df, dg, dr, p, q, N):
        self.df = df
        self.dg = dg
        self.dr = dr
        self.p = p
        self.q = q
        self.Lf = Lattice(df, df - 1, N)
        self.Lg = Lattice(dg, dg, N)
        self.Lr = Lattice(dr, dr, N)
        self.N = N

    def generate_keys():
        pass


if __name__ == "__main__":
    import doctest
    doctest.testmod()
