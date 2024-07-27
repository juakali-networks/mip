# mip

Implementation of Mobile IP [RFC 5944](https://datatracker.ietf.org/doc/html/rfc5944) for Linux, written in C.

# Install
git clone https://github.com/juakali-networks/mip.git

Adapt the mip.h file with the Mobile Node IP and Home Agent IP of your setup

<pre>mip/include/mip.h
  
/* Hardcoded IPS*/
#define MN_IP           "192.168.0.240"  
#define HA_IP           "192.168.0.85"
</pre>

<pre>cd mip/src

make clean

make</pre>

# Overview
Mobile IP is a communication protocol (created by extending the Internet Protocol) that allows users to move from one network to another while using the same IP address. It ensures that the communication will continue without the user’s sessions or connections being dropped. 

Using Mobile IP, a mobile node is able to roam from its home network to any foreign network while being always reachable through its home IP address.


This is a partial implementation of the [RFC 5944](https://datatracker.ietf.org/doc/html/rfc5944) specification. If you have any questions, comments or need any additional support, contact us on juakali.networks@gmail.com. 

Feel free to contact us if you need us to implement for you any network protocol. The auto tests used for this project can be found here (https://github.com/juakali-networks/mip/tree/master/tests). You can also contact us if you need us to create automatic tests for any protocols that you are implementing or any network devices you are developing. 


Basic use case of mip be demonstrated using the diagram below.

![Basic use case](https://github.com/juakali-networks/mip/blob/master/doc/drawing.png)


# Usage
Three Virtual machines (VMs) or PCs

VM_1, VM_2 and VM_3.

Run the commands on the VMs in the following order

On VM_1 (Foreign Agent)

<pre>sudo ./mip/src/mip -m </pre>

Foreign Agent send Agent Advertisement packet to all hosts group multicats address 224.0.0.1

On VM_3 (Home Agent)

<pre>sudo ./mip/src/mip -q </pre>

Eanbles Home Agent to send Registration Reply (RREP) packet back to Foreign Agent on receiving the RREQ packet

On VM_2 (Mobile Node)

<pre>sudo ./mip/src/mip -r </pre>

Enables Mobile Node to send Registration Request (RREQ) packet to Foreign Agent, on receieving the Agent Advertisement packet

On VM_1 (Foreign Agent)

<pre>sudo ./mip/src/mip -n </pre>

Enables Foreign Agent to send RREQ packet with care of Address to Home Agent on receiving the RREQ packet from Mobile Node

To start the complete process,

On VM_2 (Mobile Node)

<pre>sudo ./mip/src/mip -s </pre>

Mobile Node sends a router solicitation packet to the foreign agent

Foreign Agent sends multicast agent advertisement packet


If you have questions, comments or need any additional support, contact juakali.networks@gmail.com


