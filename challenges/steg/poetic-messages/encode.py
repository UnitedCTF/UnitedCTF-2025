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
    if len(sys.argv) != 4:
        print("Usage: python encode.py <input_file> <output_file> <hidden_message>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    hidden_message = sys.argv[3]

    with open(input_file, 'r') as infile:
        words = infile.read().split(" ")
        print(f"Number of words in the poem: {len(words)}")

    # convert hidden_message to binary (0011001)
    hidden_message_bin = ''.join(format(ord(char), '08b') for char in hidden_message)

    print(f"Len of hidden message: {len(hidden_message)}")

    hidden_characters = [(b"\xc2\xa0" if bit == '0' else b"\xe2\x80\x85").decode() for bit in hidden_message_bin]

    assert len(words) == len(hidden_characters) + 1, f"Number of hidden characters ({len(hidden_characters)}) + 1 does not match number of words ({len(words)})"

    final_message = ''.join(roundrobin(words, hidden_characters))

    with open(output_file, 'w') as outfile:
        outfile.write(final_message)


if __name__ == "__main__":
    main()
