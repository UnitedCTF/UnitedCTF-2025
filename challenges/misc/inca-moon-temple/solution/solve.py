from pwn import *
import base64
import sys

if len(sys.argv) != 3:
    exit(f'{sys.argv[0]} <host> <port>')

host, port = sys.argv[1:]

while True:
    p = remote(host, int(port))

    p.recvuntil(b'>> ')
    p.sendline()

    line = p.recvline_contains(b'Inca').decode()

    if 'secret' in line:
        log.success('flag: ' + p.recvline().decode())
        break

    p.close()