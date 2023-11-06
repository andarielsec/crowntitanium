#! /usr/bin/python3
"""
Justin Baum and Jadon Schuler
2 December 2020
gen_key.py
Driver code for NTRU Key Generation
"""
import argparse
from sys import exit
from ntru import NTRU, Keys
from defaults import *


def main():
    """
    Driver Code
    """
    parser = argparse.ArgumentParser(description="""
    NTRU Key Generation
    """)
    # Output File
    parser.add_argument("-pub",
                        action="store",
                        help="Public key file",
                        required=True)
    parser.add_argument("-pri",
                        action="store",
                        help="Private key file",
                        required=True)
    args = parser.parse_args()
    key = Keys(ntru)
    with open(args.pri, "w") as f:
        f.write(" ".join([str(i) for i in key.f]))
        f.write("\n")
        f.write(" ".join([str(i) for i in key.g]))
        f.write("\n")
        pass

    with open(args.pub, "w") as f:
        f.write(" ".join([str(i) for i in key.h]))
        f.write("\n")
        pass


if __name__ == "__main__":
    main()
