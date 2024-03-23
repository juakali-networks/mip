#!/bin/bash

echo "Hello, world!"
ssh lubuntu@192.168.0.34 << EOF

cd mip
git pull
cd src
rm mip
cd obj
rm mip.o
cd ..
make clean
make

EOF
