#!/bin/bash

echo "Hello, world!"
ssh lubuntu@192.168.0.34 << EOF

cd mip
git pull https://github.com/juakali-networks/mip.git
cd src
make

EOF
