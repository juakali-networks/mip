#!/bin/bash

echo "Hello, world!"
ssh admin@172.20.10.14 << EOF

cd mip
git pull https://github.com/juakali-networks/mip.git
cd src
make

EOF
