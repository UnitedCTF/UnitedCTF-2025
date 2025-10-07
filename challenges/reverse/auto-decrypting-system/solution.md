## Part 1

```bash
# Le module nbd permet de monter des images QCOW2 avec QEMU
sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 archlinux.qcow2

# Le flag est dans la partition de boot (/boot/flag.txt)
sudo mount /dev/nbd0p1 /mnt
cat /mnt/flag.txt
# flag-e0219a0535a7a028
```

## Part 2

```bash
# Source: https://wiki.archlinux.org/title/Mkinitcpio#Extracting_the_image
cd $(mktemp -d)

# unmkinitramfs d'Ubuntu fonctionne aussi
lsinitcpio -x /mnt/initramfs-linux.img

cat hooks/encrypt | grep flag
# flag-382b4c81f98402cd
```

## Part 3 & 4

Le mot de passe de déchiffrement est chiffré en XOR dans l'exécutable. La clé
de déchiffrement est calculée comme suit :

```
part_1 = sha256 of /hooks/encrypt
part_2 = sha256 of the 0x1500 first bytes starting at the beginning of the `main` symbol
part_3 = sha256 of /usr/bin/cryptsetup

key = sha256 of concatenation of part_1, part_2 and part_3
```

Cela empêche le programme de fonctionner si des breakpoints sont insérés avec gdb.
Une solution alternative est d'utiliser les "hardware breakpoints" de gdb qui ne
laissent pas de traces dans la mémoire de l'exécutable.

Script pour calculer automatiquement le mot de passe :

```python
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pwntools",
# ]
# ///

from pwn import *
import hashlib

encrypt_hook_checksum = hashlib.sha256(open("hooks/encrypt", "rb").read()).hexdigest()
cryptsetup_checksum = hashlib.sha256(open("usr/bin/cryptsetup", "rb").read()).hexdigest()

elf = ELF("usr/local/bin/auto_decrypt")

main_address = 0x23e9
main_content = elf.read(main_address, 0x1500)
main_checksum = hashlib.sha256(main_content).hexdigest()

key = hashlib.sha256((encrypt_hook_checksum + main_checksum + cryptsetup_checksum).encode()).hexdigest()

data_address = 0x4010
data = elf.read(data_address, 30)

def xor(data: bytes, key: str):
    return bytes((a ^ ord(b)) for a, b in zip(data, key))

decrypted = xor(data, key)

print(f"Password: {decrypted.decode()}")
# Everglade8-Shampoo-Ruby-Cornea
```

Utiliser le mot de passe pour se connecter avec l'utilisateur `arch`.

```bash
# Flag 3
cat /flag.txt
# flag-9bca1f01f4292830

# Flag 4
cat ~/flag.txt
# flag-657135ff66ab3614
```
