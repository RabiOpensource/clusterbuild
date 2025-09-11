cd /mnt/commonfs/samba
./configure --enable-debug --without-ldb-lmdb --without-json  --without-ad-dc --enable-selftest --with-cluster-support; make all -j$(nproc);make install
