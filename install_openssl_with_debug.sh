#/bin/bash

curl -O https://www.openssl.org/source/openssl-3.0.0.tar.gz -k
tar -zxvf openssl-3.0.0.tar.gz
cd openssl-3.0.0
./Configure --prefix=/usr/local/ssl --openssldir=/usr/local/ssl enable-ssl-trace
make
sudo make install
