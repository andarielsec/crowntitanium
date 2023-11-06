#! /usr/bin/python3
"""
Justin Baum and Jadon Schuler
2 December 2020
decrypt.py
Driver code for NTRU Decryption
"""

import argparse
from sys import exit

from defaults import ntru
from ntru import Keys
import polynomials


def main():
    """
    Driver Code
    """
    parser = argparse.ArgumentParser(description="""
    NTRU Decryption
    """)
    # Input File
    parser.add_argument("-pri",
                        action="store",
                        help="Private key file",
                        required=True)
    # Output File
    parser.add_argument("-m",
                        action="store",
                        help="Message file",
                        required=True)
    parser.add_argument("-o",
                        action="store",
                        help="Output file",
                        required=True)
    args = parser.parse_args()
    key = None
    matrix = None
    plain = None
    with open(args.pri, "r") as filey:
        f = [int(x) for x in filey.readline().split()]
        g = [int(x) for x in filey.readline().split()]
        key = Keys(ntru, f, g)
    with open(args.m, "r") as f:
        matrix = [[int(x) for x in line.split()]
                  for line in f.read().splitlines()]
    with open(args.o, "wb") as f:
        d = [key.decrypt(x) for x in matrix]
        while d[-1][-1] == 0:
            d[-1] = d[-1][:-1]
        plain = [[(int(x)).to_bytes(1, "little") for x in row] for row in d]
        flatten = lambda x: [i for sublist in plain for i in sublist]
        plain = flatten(plain)
        for i in plain:
            f.write(i)


if __name__ == "__main__":
    main()
