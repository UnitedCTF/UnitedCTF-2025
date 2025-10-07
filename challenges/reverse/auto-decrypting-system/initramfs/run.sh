#!/bin/bash

VM_DISK_PATH="/var/lib/libvirt/images/archlinux.qcow2"
PASSPHRASE="Everglade8-Shampoo-Ruby-Cornea"

set -x
set -e

docker build . -t initramfs --build-arg PASSPHRASE="$PASSPHRASE" --pull
id=$(docker create initramfs)

docker cp $id:/boot/initramfs-linux.img ./initramfs-linux.img
docker cp $id:/boot/initramfs-linux-fallback.img ./initramfs-linux-fallback.img
docker rm $id
# docker rmi initramfs

echo "Initramfs image created: initramfs-linux.img"

sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 $VM_DISK_PATH
sudo mount /dev/nbd0p1 /mnt
sudo cp -f initramfs-linux* /mnt

sudo umount /mnt
sudo qemu-nbd --disconnect /dev/nbd0
