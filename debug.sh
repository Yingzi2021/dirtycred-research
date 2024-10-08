#!/bin/bash

gnome-terminal --title="QEMU RUN HERE" -- bash -c \
"qemu-system-x86_64 \
-m 1G \
-kernel ./bzImage-5.19.0-3910-dirtycred-unpatch \
-drive file=/home/boying/test-ved/CVE-2022-1015/bookworm.img,format=raw \
-append 'root=/dev/sda rw console=ttyS0,115200 acpi=off nokaslr' \
-serial stdio -s -S \
-display none -enable-kvm \
-pidfile vm.pid \
 2>&1 | tee vm.log"

sleep 2

gnome-terminal --title="GDB RUN HERE" -- bash -c \
"sudo gdb -q \
    -ex 'set architecture i386:x86-64' \
    -ex 'add-symbol-file ./vmlinux' \
    -ex 'target remote localhost:1234' \
    -ex 'hb vfs_fallocate'
    -ex 'c'; exec bash"

# -ex 'set substitute-path /home/boying/linux-5.17/ /home/boying/test-ved/CVE-2022-1015/src/linux-5.17/' \
