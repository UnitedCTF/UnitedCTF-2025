#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pwntools",
# ]
# ///

from pwn import *
import hashlib

data = PLACEHOLDER

encrypt_hook_checksum = hashlib.sha256(open("/usr/lib/initcpio/hooks/encrypt", "rb").read()).hexdigest()
cryptsetup_checksum = hashlib.sha256(open("/usr/bin/cryptsetup", "rb").read()).hexdigest()

elf = ELF("./auto_decrypt")

main_address = elf.symbols["main"]

# Read main content
main_content = elf.read(main_address, 0x1500)

main_checksum = hashlib.sha256(main_content).hexdigest()

key = hashlib.sha256((encrypt_hook_checksum + main_checksum + cryptsetup_checksum).encode()).hexdigest()

def xor(data: str, key: str):
    return bytes((ord(a) ^ ord(b)) for a, b in zip(data, key))

encrypted = xor(data, key)

# Patch the binary with the new passphrase
elf.write(elf.symbols["data"], encrypted)

# Save the modified ELF
elf.save("./auto_decrypt")
