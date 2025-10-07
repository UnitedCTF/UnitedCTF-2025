#!/usr/bin/env python3
import sys


def step1_decrypt(jumbled_data):
    key = 0xBAADF00DDEADBEEF
    result = ""

    for i in range(2):
        chunk = jumbled_data[i * 8 : (i + 1) * 8]
        data = int.from_bytes(chunk, "big")

        decrypted = data ^ key

        result += decrypted.to_bytes(8, "big").decode("ascii", errors="ignore")

    return result


def step2_validate_password(user_input):
    expected_password = "R3VER53!"
    return user_input == expected_password


def step3_decrypt(jumbled_data, start_offset=16):
    key = int.from_bytes("R3VER53!".encode(), "big")
    key_increment = 0x1111111111111111
    result = ""

    for i in range(3):
        chunk = jumbled_data[start_offset + i * 8 : start_offset + (i + 1) * 8]
        data = int.from_bytes(chunk, "big")

        temp = data ^ key

        key = (key + key_increment) & 0xFFFFFFFFFFFFFFFF

        decrypted = temp ^ key

        result += decrypted.to_bytes(8, "big").decode("ascii", errors="ignore")

    return result


def decrypt_jumbled_flag(jumbled_file_path):
    with open(jumbled_file_path, "rb") as f:
        data = f.read()

    step1_result = step1_decrypt(data[:16])

    if not step2_validate_password(input("Enter password: ")):
        raise ValueError("Invalid password")

    step3_result = step3_decrypt(data, start_offset=16)

    flag = step1_result + step3_result
    return flag.strip("\x00")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <jumbled_flag_file>")
        sys.exit(1)
        
    jumbled_file = sys.argv[1]

    try:
        result = decrypt_jumbled_flag(jumbled_file)
        print(f"Flag: {result}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
