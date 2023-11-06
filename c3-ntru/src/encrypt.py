#! /usr/bin/python3
"""
Justin Baum and Jadon Schuler
2 December 2020
encrypt.py
Driver code for NTRU Encryption
"""
import argparse
from sys import exit

from defaults import ntru
from ntru import Encrypt
import polynomials


def main():
    """
    Driver Code
    """
    parser = argparse.ArgumentParser(description="""
    NTRU Encryption
    """)
    # Input File
    parser.add_argument("-pub",
                        action="store",
                        help="Public key file",
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
    pub = args.pub
    h = None
    m = args.m
    message = []
    o = args.o
    cipher = None
    with open(m, "rb") as f:
        i = 0
        N = ntru.N
        currbyte = [0 for _ in range(N)]
        data = True
        while data:
            data = f.read(1)
            j = int.from_bytes(data, "little")
            currbyte[i] = j
            if i == N - 1:
                currbyte = polynomials.reduce_mod(currbyte, ntru.p)
                message.append(currbyte)
                i = 0
                currbyte = [0 for _ in range(N)]
                continue
            i += 1
        if (any([i != 0 for i in currbyte])): message.append(currbyte)
    with open(pub, "r") as f:
        h = [int(x) for x in f.readline().split()]
        enc = Encrypt(h, ntru)
        cipher = [enc.encrypt(i) for i in message]
    with open(o, "w") as ou:
        s = "\n".join([" ".join([str(v) for v in row]) for row in cipher])
        ou.write(s)


if __name__ == "__main__":
    main()
