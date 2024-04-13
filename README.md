# mip
Mobile IP implementation for Linux in C

implementation of Mobile IP RFC 5944 for Linux, written in C.

# Install
git clone https://github.com/juakali-networks/mip.git

cd /mip/src

make clean

make

# Overview
Mobile IP is a communication protocol (created by extending Internet Protocol, IP) that allows the users to move from one network to another with the same IP address. It ensures that the communication will continue without the user’s sessions or connections being dropped. 

Using Mobile IP, a mobile node is able to roam from an its home network to any foreign network while being always reachable through its home IP address.


THis is a partial implemntation of RFC 5944 specification. In case you are interested inthe full implementation, please contact us on juakali.networks@gmail.com


Basic use came be demonstrated using the diagram below.

[text](HLD.pdf)
