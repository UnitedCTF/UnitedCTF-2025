How to create image:

1. Create an ArchLinux VM using virt-manager.
2. Run `./run-all.sh` inside `archinstall` after setting the right variables (encrypted disk password is in `archinstall/user_credentials.json`).
3. Run `./run.sh` inside `initramfs` after setting the right variables.
4. Copy archlinux.qcow2 image, then run the following to shrink and generate VMWare/VirtualBox versions:

```bash
qemu-img convert -O qcow2 archlinux.qcow2 shrunk.qcow2
qemu-img convert -O vdi archlinux.qcow2 archlinux.vdi
qemu-img convert -O vmdk archlinux.qcow2 archlinux.vmdk
```
