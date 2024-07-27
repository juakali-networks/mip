
# Test setup

Two virtual machines (VMs).

On Host PC, enable logging in without password by running the following commands for each VM.
<pre>ssh-keygen</pre>
<pre>ssh-copy-id vm_username@vm_IP</pre>
<pre>ssh-copy-id vm_username@vm_IP</pre>

on Host PC, install SCP
<pre>cd /usr/local/lib/python3.8/dist-packages</pre>
<pre>sudo git clone https://github.com/jbardin/scp.py</pre>
Rename the file from scp.py to scp
<pre>mv scp.py scp</pre>

Install wireshark on your host PC.
Install pyshark on your host PC.



Clone the rdisc repository. 
<pre>git clone https://github.com/juakali-networks/rdisc/tree/master></pre>

# Run tests

Navigate to the tests folder and in the python files, adapt the IP addresses and VM usernames and passwords to match your own.

Run the VM configuration script
<pre>cd tests</pre>
<pre>python3 configure_VMs.py</pre>

Run the tests

<pre>agent_advert.py</pre>
<pre>solicit_agent_advert.py</pre>
<pre>mobile_node_registration_request.py</pre>
<pre>home_agent_registration_request.py</pre>
<pre>home_agent_registration_reply.py</pre> 
<pre>foreign_agent_registration_reply.py</pre>

To run the complete chain, run 
<pre>foreign_agent_registration_reply.py</pre>
If you have any questions, comments or need any additional support, contact us on juakali.networks@gmail.com.







