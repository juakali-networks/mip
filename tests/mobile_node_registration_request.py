
import subprocess
import re
from subprocess import PIPE
import pyshark
import os
import time
import paramiko
from scp.scp import SCPClient
# from scp.SCPClient import SCPClient

class mn_reg_req():

    def __init__(self):

        # Configs. Change your settings here
        self._pwd = "lubuntu"
        self._user_name = "lubuntu"

        self._ip1 = "192.168.0.34"
        self._ip2 = "192.168.0.240"
        self._ip3 = "192.168.0.85"
  
        self._rreq_msg_type = 1
        self._dest_port = "434"
        self._dest_addr = self._ip1
    
        self._file = 'mn_reg_req.pcap'
        self._local_path = '/home/dancer/mip/tests/Results'

 
    def step_1(self):
     
        subprocess.run(["rm Results/reg_req.pcap"], shell=True, capture_output=False)

        print("Mobile Node sending Registration Reply Packet to Foreign Adent\n")

        vm_user = "%s@%s" % (self._user_name, self._ip2)
        try:
            ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  ./mip/src/mip -r" % self._pwd],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                                bufsize=0)
            ma_process.communicate()
            ma_process.kill()
        
        except Exception as err:
            print("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self._ip2, err))
            return False
    
        time.sleep(5)

        print("\nForeign Agent sending Agent Advertisement multicast packet\n")
       
        vm_user = "%s@%s" % (self._user_name, self._ip1)
    
        try:
            aa_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  ./mip/src/mip -m" % self._pwd],
                                    stdin=subprocess.PIPE, 
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
            
            aa_process.communicate()
            aa_process.kill()
            
        except Exception as err:
            print("Connecting to Foriegn Agent VM with IP %s failed with error %s" % (self._ip1, err))
            return False


        state = self.check_packet_header()

        if state is True:
            print("Test Passed")
        else:
            print("Test Failed")

        self.clean_up()

        return state


    def check_packet_header(self):
        """
        Check IP packet header
        """
        state = list()

 
        vm_user = "%s@%s" % (self._user_name, self._ip1)

        try:
            ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  tcpdump -i enp0s3 port 434 -c 1 -w mn_reg_req.pcap\n" % self._pwd],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)

            ma_process.communicate()
            ma_process.kill()

        except Exception as err:
             print("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self._ip1, err))
             return False

        ssh = self.createSSHClient(self._ip1, 22, self._user_name, self._pwd)
        scp = SCPClient(ssh.get_transport())
        scp.get(remote_path=self._file, local_path=self._local_path)
        scp.close()

        vm_user = "%s@%s" % (self._user_name, self._ip1)

        ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S rm mn_reg_req.pcap\n" % self._pwd],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                    bufsize=0)
        ma_process.communicate()

        ma_process.kill()

        # read pcap file and read packet fields
        pcap_file = pyshark.FileCapture('/home/dancer/mip/tests/Results/mn_reg_req.pcap')
        
        try:
            for packet in pcap_file:

                dst_addr = packet.layers[1].dst
                print("Destination Address %s" % dst_addr)
                dst_port = packet.layers[2].dstport
                print("Destination Port %s" % dst_port)
                mip_type = int(packet.layers[3].type, 16)
                print("Mobile IP Type %s" % type(mip_type))
                care_off_addr = packet.layers[3].coa
                print("Care of Address %s" % care_off_addr)
                home_addr = packet.layers[3].homeaddr
                print("Home Address %s" % home_addr)
                home_agent = packet.layers[3].haaddr
                print("Home Agent %s" % home_agent)

                
                if dst_addr == self._dest_addr:
                    print("\nForeign agent received registration request message from Mobile Node on its IP address %s as expected\n" % dst_addr)
                    state.append(True)
                else:
                    print("\nRegistration request message is Not sent to the Foreign agent IP address %s but to another destination address %s -- Test Failed\n"% (self._dest_addr, dst_addr))
                    state.append(False)

                if dst_port == self._dest_port:
                    print("\nReceived registration request message is sent to the correct port %s as expected\n" % dst_port)
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

                if  care_off_addr == self._ip1:
                    print("\nForeign agent received registration with the correct Care of IP address %s as expected\n" % care_off_addr)
                    state.append(True)
                else:
                    print("\nRegistration request message is sent to the Foreign agent with the wrong care of address IPP %s, Not the expected address %s -- Test Failed\n" % (self._ip2, care_off_addr))
                    state.append(False)


                if  home_addr == self._ip2:
                    print("\nForeign agent received registration with the correct Home address IP address %s as expected\n" % home_addr)
                    state.append(True)
                else:
                    print("\nRegistration request message is sent to the Foreign agent with the wrong Home Address IP %s, Not the expected address %s -- Test Failed\n" % (home_addr, self._ip2))
                    state.append(False)

                if  home_agent == self._ip3:
                    print("\nForeign agent received registration with the correct Home Agent IP address %s as expected\n" % home_agent)
                    state.append(True)
                else:
                    print("\nRegistration request message is sent to the Foreign agent with the wrong Home Agent IP %s, Not the expected address %s -- Test Failed\n" % (home_agent, self._ip3))
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

    def clean_up(self):
        """
        Reboot VMs
        """
        vms = [self._ip1, self._ip2, self._ip3]

        for ip in vms:
            try:
                vm_user = "%s@%s" % (self._user_name, ip)
                vm_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  reboot\n" % self._pwd],
                                        stdin=subprocess.PIPE,
                                        stdout = subprocess.PIPE,
                                        universal_newlines=True,
                                    bufsize=0)

                vm_process.communicate()
                vm_process.kill()
                print("Rebooted VM with IP %s" % ip)
            except Exception as err:
                print("Failed to reboot VM with IP %s  with error %s" % (ip, err))

        time.sleep(60)

        return True

mn_reg_req().step_1()





 












