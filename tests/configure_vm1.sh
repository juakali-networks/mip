#!/bin/bash

echo "Hello, world!"
ssh lubuntu@192.168.0.53 << EOF

cd mip
echo "$(ls)"
echo $(pwd)
git pull
cd src
echo "$(ls)"
rm mip
echo "$(ls)"
cd obj
rm mip.o
cd ..
make clean
make

EOF
