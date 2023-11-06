"""
Copyright 2020
Jadon Schuler & Justin Baum
Utilities
utils.py
Co-authored-by: Jadon Schuler <jtschuler007@gmail.com>
"""


# pylint: disable=invalid-name
def general_linear_congruence(a: int, modulus: int, k: int) -> int:
    """
    Linear Congruence Solver
    Extended Euclidean Algorithm
    a*x === (cong) k mod m
    """
    original_modulus = modulus
    y = 0
    x = k
    if modulus <= 1:
        return 0
    while a > 1:
        quotient = a // modulus
        (a, modulus) = (modulus, a % modulus)
        (x, y) = (y, x - quotient * y)
    return x % original_modulus


def multiplicative_inverse(a: int, modulus: int) -> int:
    """
    Multiplicative inverse
    a*x === (congruent) 1 mod modulus
    """
    return general_linear_congruence(a, modulus, 1)
