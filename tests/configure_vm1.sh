#!/bin/bash

echo "Hello, world!"
ssh lubuntu@192.168.0.53 << EOF

cd mip
echo $(pwd)
git pull
cd src
echo $(pwd)
rm mip
echo $(pwd)
cd obj
echo $(pwd)
rm mip.o
echo $(pwd)
cd ..
echo $(pwd)
make clean
make

EOF
