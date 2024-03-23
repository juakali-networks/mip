#!/bin/bash

echo "Hello, world!"
ssh lubuntu@192.168.0.34 << EOF

cd mip
git pull
cd src
m mip
rm obj/mip.o
make clean
make

EOF
