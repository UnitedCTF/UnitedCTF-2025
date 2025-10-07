#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "more_itertools",
# ]
# ///

import sys

from more_itertools import roundrobin


def main():
    if len(sys.argv) != 2:
        print("Usage: python decode.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]

    with open(input_file, 'r') as infile:
        content = infile.read()

    key = ''

    for char in content:
        if char.encode() == b'\xc2\xa0':
            key += '0'
        elif char.encode() == b'\xe2\x80\x85':
            key += '1'

    # Convert binary string to characters
    hidden_message = ''.join(chr(int(key[i:i + 8], 2)) for i in range(0, len(key), 8))

    print(f"Hidden message: {hidden_message}")


if __name__ == "__main__":
    main()
