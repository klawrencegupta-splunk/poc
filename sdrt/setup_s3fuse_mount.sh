#!/bin/bash

yum update
yum install automake fuse fuse-devel gcc-c++ git libcurl-devel libxml2-devel make openssl-devel
cd /home/ec2-user
git clone https://github.com/s3fs-fuse/s3fs-fuse.git
cd  s3fs-fuse
./autogen.sh 
sleep 5s
./configure; make; make install
echo $(which s3fs)
touch /etc/passwd-s3fs
echo <access_key>:<secret_key> > /etc/passwd-s3fs
chmod 600 /etc/passwd-s3fs
mkdir /s3
/usr/local/bin/s3fs <bucket_name> -o use_cache=/tmp -o allow_other -o uid=1001 -o mp_umask=002 -o multireq_max=5 /s3
