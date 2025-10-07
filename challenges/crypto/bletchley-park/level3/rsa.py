from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes


def weak_e_small_message():
    exp = 9
    key = RSA.generate(3072, e=exp)
    n = key.n
    e = key.e

    message = b"flag-b5ff1438-4bf6-4b1f-8a02-e9edd1dbb545"
    m = bytes_to_long(message)

    c = pow(m, e, n)

    print("=== CHALLENGE DATA ===")
    print(f"n = {hex(n)}")
    print(f"e = {hex(e)}")
    print(f"c = {hex(c)}")
    print()



if __name__ == "__main__":
    weak_e_small_message()
