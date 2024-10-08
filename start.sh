qemu-system-x86_64  \
-m 4G  \
-smp 4 \
-kernel /home/boying/bzImage   \
-append "console=ttyS0 root=/dev/sda rw earlyprintk=serial net.ifnames=0 nokaslr no_hash_pointers"     \
-drive file=/home/boying/bookworm.img,format=raw \
-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
-net nic,model=e1000 \
-nographic  \
-pidfile vm.pid \
-s \
2>&1 | tee vm.log
