"""
Copyright 2020
Jadon Schuler & Justin Baum
Polynomial Utility Functions
polynomials.py
"""
"""
A polynomial will be a 0 indexed list.
3 + 2x + 5x^2
[3, 2, 5]
0 + 5x + 0x^2 + 11x^3
[0, 5, 0, 11]
"""

import utils
from sympy import Matrix

# pylint: disable=invalid-name


def normalize(polynomial1, polynomial2, N=None):
    l = max(len(polynomial1), len(polynomial2))
    N = N if N else l
    p1l = len(polynomial1)
    p2l = len(polynomial2)
    poly1 = [polynomial1[i] if p1l > i else 0 for i in range(N)]
    poly2 = [polynomial2[i] if p2l > i else 0 for i in range(N)]
    return (N, poly1, poly2)


def multiplication(polynomial1, polynomial2, modulus=None, N=None):
    """
    Convolution product
    >>> multiplication([1,2,3],[2,5,7])
    [31, 30, 23]
    >>> multiplication([-1,1,1], [2,2,9,5,15], 16)
    [2, 15, 11, 6, 15]
    """
    (N, poly1, poly2) = normalize(polynomial1, polynomial2, N)
    result = [0 for i in range(N)]
    for i in range(N):
        for j in range(N):
            index = (i + j) % N
            result[index] += poly1[i] * poly2[j]
            if modulus: result[index] %= modulus
    return result


def addition(polynomial1, polynomial2, modulus=None, N=None):
    """
    >>> addition([1,2,3], [2,5,7])
    [3, 7, 10]
    >>> addition([1,2,3], [2,5,7],7)
    [3, 0, 3]
    """
    (_N, poly1, poly2) = normalize(polynomial1, polynomial2, N)
    if modulus:
        return [(x[0] + x[1]) % modulus for x in zip(poly1, poly2)]
    return [(x[0] + x[1]) for x in zip(poly1, poly2)]


def subtraction(polynomial1, polynomial2, modulus=None, N=None):
    """
    >>> subtraction([1,2,3], [0,1,2], 3)
    [1, 1, 1]
    """
    (_1N, poly1, poly2) = normalize(polynomial1, polynomial2, N)
    if modulus:
        return [(x[0] - x[1]) % modulus for x in zip(poly1, poly2)]
    return [(x[0] - x[1]) for x in zip(poly1, poly2)]


def trim(poly_):
    """
    >>> trim([1,2,3,4,0,0,6,0,0,0])
    [1, 2, 3, 4, 0, 0, 6]
    """
    poly = [i for i in poly_]
    while len(poly) > 0 and poly[-1] == 0:
        poly = poly[:-1]
    return poly


def degree(poly):
    """
    >>> degree([1,2,3,0,0,0])
    2
    >>> degree([1,2,3,5,0,0,0,1,2,3,4,5,0,0])
    11
    """
    return len(trim(poly)) - 1


def leading_coefficient(poly):
    """
    >>> leading_coefficient([1,2,3,0,0,0])
    3
    >>> leading_coefficient([1,2,3,5,0,0,0,1,2,3,4,5,0,0])
    5
    """
    return trim(poly)[-1]


def getnullmatrix(polynomial, N):
    """
    >>> getnullmatrix([-1,1,1], 5)
    [[-1, 0, 0, 1, 1, 1], [1, -1, 0, 0, 1, 0], [1, 1, -1, 0, 0, 0], [0, 1, 1, -1, 0, 0], [0, 0, 1, 1, -1, 0]]
    """
    """
    Linear Algebra
    [a,b,c] * [d,e,f] (mod p/q) = 1
    [
    ad + bf + ce = 1, 
    ae + db + fc = 0, 
    af + dc + be = 0
    ]
        2f, 1d, 3e, 1
        3f, 2d, 1e, 0
        1f, 3d, 2e, 0
    [f[2,1,3], d[3,2,1], e[1,3,2],[1,0,0]] solve for f d e (mod p)
    [
[-1,  0,  0,  1,  1, 1],
[ 1, -1,  0,  0,  1, 0],
[ 1,  1, -1,  0,  0, 0],
[ 0,  1,  1, -1,  0, 0],
[ 0,  0,  1,  1, -1, 0]]
    """
    d = degree(polynomial)
    matrix = [[0 for _ in range(N + 1)] for _ in range(N)]
    matrix[0][N] = 1
    for i in range(N):
        for j in range(d + 1):
            matrix[(i + j) % N][i] = polynomial[j]
    return matrix


def getnullvector(polynomial, modulus: int, N):
    """
    >>> getnullvector([-1,1,1], 16, 5)
    [10, 9, 3, 12, 15]
    >>> getnullvector([-1,1,1], 3, 5)
    [2, 0, 2, 2, 1]
    >>> getnullvector([-1,1,1], 16, 4)
    [3, 10, 13, 7]
    """
    matrix = Matrix(getnullmatrix(polynomial, N))
    solution = (-matrix.nullspace()[0])[:-1]
    for j in range(5):
        for i in range(len(solution)):
            if solution[i].q != 1:
                solution = [
                    solution[i] * solution[i].q for i in range(len(solution))
                ]
            break
    first_row = list(matrix)[:N]
    # [2,3,5]
    # Calculating the first equation like
    # 2c + 4c + 5c = 1
    eq_val = sum(map(lambda x: x[0] * x[1], zip(first_row, solution)))
    m = utils.multiplicative_inverse(eq_val, modulus)
    solution = list(map(lambda x: (m * (x % modulus)), solution))
    solution = list(map(lambda x: x % modulus, solution))
    return solution


def scalar_mult(polynomial, k, modulus):
    """
    >>> scalar_mult([1,2,3,4,5], 3, 7)
    [3, 6, 2, 5, 1]
    """
    return [(k * i) % modulus for i in polynomial]


def reduce_mod(polynomial, mod):
    """
    #>>> reduce_mod([1,2,3,4,5,6,7,8], 5)
    [1, 2, -2, -1, 0, 1, 2, -2]
    #>>> reduce_mod([2,-1,11,-10,-1], 16)
    [2, -1, -5, 6, -1]
    >>> reduce_mod([2,0,1,1,0], 3)
    [-1, 0, 1, 1, 0]
    """
    bound = mod // 2
    return list(
        map(lambda x: x % mod
            if (x % mod) <= bound else (x % mod) - mod, polynomial))


def getinverse(polynomial, modulus: int, N):
    """
    >>> getinverse([-1,1,1], 16, 5)
    [10, 9, 3, 12, 15]
    >>> getinverse([-1,1,1], 3, 5)
    [2, 0, 2, 2, 1]
    """
    d = degree(polynomial)
    matrix = [[0 for _ in range(N)] for _ in range(N)]
    for i in range(N):
        for j in range(d + 1):
            matrix[(i + j) % N][i] = polynomial[j]

    matrix = Matrix(matrix)
    det = matrix.det()

    # We can remove this since there will always be a solution
    # Just a sanity check
    if det == 0:
        raise Exception("Singular matrix")
    matrix_inv = matrix.inv() * det * utils.multiplicative_inverse(
        det, modulus)

    v = [0 for _ in range(N)]
    v[0] = 1
    v = Matrix(v)
    result = matrix_inv * v
    inverse = [result[i] % modulus for i in range(len(result))]
    return inverse


def strpoly(poly):
    s = ""
    deg = 0
    for (j, i) in enumerate(poly):
        s += (str(i) + ("x^{}".format(deg) if deg > 0 else "") +
              " + ") if i != 0 else ""
        deg += 1
    return s


if __name__ == "__main__":
    import doctest
    doctest.testmod()
