#!/bin/bash

echo "Hello, world!"
ssh lubuntu@192.168.0.53 << EOF

cd mip
git pull https://github.com/juakali-networks/mip.git
cd src
rm mip
rm obj/mip.o
make clean
make

EOF
