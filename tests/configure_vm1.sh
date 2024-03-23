#!/bin/bash

echo "Hello, world!"
ssh lubuntu@192.168.0.53 << EOF

cd mip
echo "aa!"

echo $(pwd)
echo "bbb!"

git pull
echo "ccc!"

cd src
echo "ddd!"

echo $(pwd)
echo "eee!"

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
