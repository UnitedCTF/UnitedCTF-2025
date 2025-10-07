#!/bin/bash

echo "Setting up fscrypt for encrypted home directory..."
tune2fs -O encrypt /dev/mapper/ainstvda2
arch-chroot /mnt fscrypt setup --force --quiet
echo "auth optional pam_fscrypt.so" >> /mnt/etc/pam.d/system-login
sed -i "s/password *include *system-auth/\0\nsession [success=1 default=ignore] pam_succeed_if.so service = systemd-user quiet\nsession optional pam_fscrypt.so/" /mnt/etc/pam.d/system-login
echo "password optional pam_fscrypt.so" >> /mnt/etc/pam.d/passwd
sed -i 's/password *required *pam_unix.so .*shadow/\0 rounds=1000000/' /mnt/etc/pam.d/system-auth

echo "Changing password for user 'arch'..."
arch-chroot /mnt passwd arch

echo "Creating encrypted home directory for user 'arch'..."
mv /mnt/home/arch{,.old}
mkdir /mnt/home/arch
chown 1000:1000 /mnt/home/arch
arch-chroot /mnt fscrypt encrypt /home/arch --user=arch --source=pam_passphrase
mv /mnt/home/arch.old/.[!.]* /mnt/home/arch/
rm -r /mnt/home/arch.old

echo "Inserting flags"
cat flag1.txt > /mnt/boot/flag.txt
cat flag3.txt > /mnt/flag.txt
cat flag4.txt > /mnt/home/arch/flag.txt
cat launch_codes.txt > /mnt/home/arch/launch_codes.txt
cat issue.txt > /mnt/etc/issue
