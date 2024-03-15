
import subprocess
import re
from subprocess import PIPE
import pyshark
import os
import time
import paramiko
from scp.scp import SCPClient
# from scp.SCPClient import SCPClient

class reg_req():

    def __init__(self):

        # Configs. Change your settings here
        self._pwd = "admin"
        self._ip1 = "192.168.0.34"
        self._ip2 = "192.168.0.53"
  
        self._rreq_msg_type = 1
        self._dest_port = "434"
        self._file = 'reg_req.pcap'
        self._local_path = '/home/peter/mip/tests/Results'

 
    def step_1(self):
     
        subprocess.run(["rm Results/reg_req.pcap"], shell=True, capture_output=False)

        print("\nForeign Agent sending Agent Advertisement multicast packet\n")
       
        vm_user = "admin@%s" % self._ip1
        try:
            aa_process = subprocess.Popen(['ssh','-tt', vm_user, "echo 'admin' | sudo -S  ./mip/src/mip -m"],
                                    stdin=subprocess.PIPE, 
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
            
            aa_process.communicate()
            aa_process.kill()
            
        except Exception as err:
            print("Connecting to Foriegn Agent VM with IP %s failed with error %s" % (self._ip1, err))
            return False

        print("Mobile Node sending Registration Reply Packet to Foreign Adent\n")

        time.sleep(5)

        vm_user = "admin@%s" % self._ip2

        try:
            ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo 'admin' | sudo -S  ./mip/src/mip -r"],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                                bufsize=0)
            ma_process.communicate()
            ma_process.kill()
        
        except Exception as err:
            print("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self._ip2, err))
            return False
    

        state = self.check_packet_header()

        if state is True:
            print("Test Passed")
        else:
            print("Test Failed")

        return state


    def check_packet_header(self):
        """
        Check IP packet header
        """
        state = list()

        self._local_path = '/home/peter/mip/tests/Results'
 
        vm_user = "admin@%s" % self._ip1

        try:
            ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo 'admin' | sudo -S  tcpdump -i enp0s3 port 434 -c 1 -w reg_req.pcap\n"],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
            
            ma_process.communicate()
            
            ma_process.kill()

        except Exception as err:
             print("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self._ip2, err))
             return False

        
        ssh = self.createSSHClient("172.20.10.14", 22, "admin", "admin")
        scp = SCPClient(ssh.get_transport())
        scp.get(remote_path=self._file, local_path=self._local_path)
        scp.close()

        vm_user = "admin@%s" % self._ip1

        ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo 'admin' | sudo -S rm reg_req.pcap\n"],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                    bufsize=0)
        ma_process.communicate()

        ma_process.kill()

        # read pcap file and read packet fields
        pcap_file = pyshark.FileCapture('/home/peter/mip/tests/Results/reg_req.pcap')
        
        try:
            for packet in pcap_file:

                dst_addr = packet.layers[1].dst
                dst_port = packet.layers[2].dstport
                mip_type = packet.layers[3].mip.type
                care_off_addr = packet.layers[3].coa
                home_addr = packet.layers[3].homeaddr
                home_agent = packet.layers[3].haaddr
                
                if dst_addr == self._dest_addr:
                    print("\nForeign agent received registration request message from Mobile Node on its IP address %s as expected\n" % dst_addr)
                    state.append(True)
                else:
                    print("\nRegistration request message is Not sent to the Foreign agent IP address %s but to another destination address %s -- Test Failed\n"% (self._dest_addr, dst_addr))
                    state.append(False)

                if dst_port == self._dest_port:
                    print("\nReceived registration request message is sent to the correct port %s as expected\n" % dst_addr)
                    state.append(True)
                else:
                    print("\nReceived registration request message is not sent to the expected port %s but to wrong port %s - Test Failed\n" % (self._dest_port, dst_port))
                    state.append(False)


                if mip_type == self._rreq_msg_type:
                    print("\nRegistration Request message is sent with the correct message type %s\n" % self._rreq_msg_type)
                    state.append(True)
                else:
                    print("\nRegistration Request message is sent with wrong message type number %s and not type number %s --Test Failed\n" % (mip_type, self._rreq_msg_type))
                    state.append(False)

                if  care_off_addr == self._ip2:
                    print("\nForeign agent received registration with the correct Care of IP address %s as expected\n" % care_off_addr)
                    state.append(True)
                else:
                    print("\nRegistration request message is sent to the Foreign agent with the wrong care of address IPP %s, Not the expected address %s -- Test Failed\n" % (self._ip2, care_off_addr))
                    state.append(False)


                if  home_addr == self._ip2:
                    print("\nForeign agent received registration with the correct Home address IP address %s as expected\n" % home_addr)
                    state.append(True)
                else:
                    print("\nRegistration request message is sent to the Foreign agent with the wrong Home Address IP %s, Not the expected address %s -- Test Failed\n" % (self._ip2, home_addr))
                    state.append(False)

                if  home_agent == self._ip2:
                    print("\nForeign agent received registration with the correct Home Agent IP address %s as expected\n" % home_agent)
                    state.append(True)
                else:
                    print("\nRegistration request message is sent to the Foreign agent with the wrong Home Agent IP %s, Not the expected address %s -- Test Failed\n" % (self._ip2, home_agent))
                    state.append(False)




        except Exception as err:
            print("Failed to read packet with error %s" % err)
            state.append(False)
        
        return all(state) if state else False


    def createSSHClient(self, server, port, user, password):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(server, port, user, password)
        return client

    def clean_up(self, ma_process, aa_process):
        """
        Restore the VMs to there original state
        """
        try:
            aa_process.kill()
        except Exception as err:
            print("Failed to kill process  with error %s" % err)


        try:
            ma_process.kill()
        except Exception as err:
            print("Failed to kill process  with error %s" % err)

        return True

reg_req().step_1()





 











