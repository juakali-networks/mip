
import subprocess
import re
from subprocess import PIPE
import pyshark
import os
import time
import paramiko
from scp.scp import SCPClient
import threading

# from scp.SCPClient import SCPClient

class ha_reg_req():

    def __init__(self):

        # Configs. Change your settings here
        self._pwd = "lubuntu"
        self._user_name = "lubuntu"

        self._ip1 = "192.168.0.34"
        self._ip2 = "192.168.0.240"
        self._ip3 = "192.168.0.85"

  
        self._rrep_msg_type = 3
        self._dest_port = "434"
    
        self._file = 'fa_reg_rep.pcap'
        self._local_path = '/home/dancer/mip/tests/Results'

 
    def step_1(self):
     
        subprocess.run(["rm Results/fa_reg_rep.pcap"], shell=True, capture_output=False)


        vm_user = "%s@%s" % (self._user_name, self._ip2)
        try:
            vm2_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  ./mip/src/mip -r" % self._pwd],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                                bufsize=0)
            vm2_process.communicate()
            vm2_process.kill()
        
        except Exception as err:
            print("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self._ip2, err))
            return False
    
        time.sleep(10)
        # print("Mobile Node sending Registration Reply Packet to Foreign Adent\n")
        vm_user = "%s@%s" % (self._user_name, self._ip1)
        try:
            vm1_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  ./mip/src/mip -j" % self._pwd],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                                bufsize=0)
            vm1_process.communicate()
            vm1_process.kill()
        
        except Exception as err:
            print("Connecting to Foreign Agent VM with IP %s failed with error %s" % (self._ip1, err))
            return False
    
        time.sleep(10)

        vm_user = "%s@%s" % (self._user_name, self._ip3)
        try:
            vm3_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  ./mip/src/mip -q" % self._pwd],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                                bufsize=0)
            vm3_process.communicate()
            vm3_process.kill()
        
        except Exception as err:
            print("Connecting to Home Agent VM with IP %s failed with error %s" % (self._ip3, err))
            return False
    

        time.sleep(10)

        # print("\nForeign Agent sending Registration Request message with Care of Address to Home Agent\n")
       
        vm_user = "%s@%s" % (self._user_name, self._ip1)
    
        try:
            vm1_process_2 = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  ./mip/src/mip -n" % self._pwd],
                                    stdin=subprocess.PIPE, 
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
            
            vm1_process_2.communicate()
            vm1_process_2.kill()
            
        except Exception as err:
            print("Connecting to Foriegn Agent VM with IP %s failed with error %s" % (self._ip1, err))
            return False

        time.sleep(10)

        return True
    

    def step_2(self):
      
        # Create threads for each command
        thread1 = threading.Thread(target=self.capture_packet)
        thread2 = threading.Thread(target=self.run_agent_advert)
        
        # Start both threads
        thread1.start()
        time.sleep(5)
        thread2.start()

        # Wait for both threads to finish
        thread1.join()
        thread2.join()

        print("Both commands completed")


        state = self.read_packet_header()

        if state is True:
            print("Test Passed")
        else:
            print("Test Failed")

        # self.clean_up()

        return state


    def read_packet_header(self):
        """
        Check IP packet header
        """
        state = list()


        ssh = self.createSSHClient(self._ip2, 22, self._user_name, self._pwd)
        scp = SCPClient(ssh.get_transport())
        scp.get(remote_path=self._file, local_path=self._local_path)
        scp.close()

        vm_user = "%s@%s" % (self._user_name, self._ip2)

        ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S rm fa_reg_rep.pcap\n" % self._pwd],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                    bufsize=0)
        ma_process.communicate()

        ma_process.kill()

        # read pcap file and read packet fields
        pcap_file = pyshark.FileCapture('/home/dancer/mip/tests/Results/fa_reg_rep.pcap')
        
        try:
            for packet in pcap_file:

                dst_addr = packet.layers[1].dst
                print("Destination Address %s" % dst_addr)
                dst_port = packet.layers[2].dstport
                print("Destination Port %s" % dst_port)
                mip_type = int(packet.layers[3].type, 16)
                print("Mobile IP Type %s" % type(mip_type))
                home_addr = packet.layers[3].homeaddr
                print("Home Address %s" % home_addr)
                home_agent = packet.layers[3].haaddr
                print("Home Agent %s" % home_agent)
                
                if dst_addr == self._ip2:
                    print("\nMobile Node received registration reply message from Foreign Agent on its IP address %s as expected\n" % dst_addr)
                    state.append(True)
                else:
                    print("\nRegistration reply message is Not sent from the Foreign agent IP address %s but to another destination address %s -- Test Failed\n"% (self._ip2, dst_addr))
                    state.append(False)

                if dst_port == self._dest_port:
                    print("\nReceived registration reply message is sent to the correct port %s as expected\n" % dst_port)
                    state.append(True)
                else:
                    print("\nReceived registration reply message is not sent to the expected port %s but to wrong port %s - Test Failed\n" % (self._dest_port, dst_port))
                    state.append(False)

                if mip_type == self._rrep_msg_type:
                    print("\nRegistration reply message is sent with the correct message type %s\n" % self._rrep_msg_type)
                    state.append(True)
                else:
                    print("\nRegistration reply message is sent with wrong message type number %s and not type number %s --Test Failed\n" % (mip_type, self._rrep_msg_type))
                    state.append(False)

                if  home_addr == self._ip2:
                    print("\nMobile Node received registration reply with the correct Home address IP address %s as expected\n" % home_addr)
                    state.append(True)
                else:
                    print("\nRegistration reply message is sent to the Mobile Node with the wrong Home Address IP %s, Not the expected address %s -- Test Failed\n" % (home_addr, self._ip2))
                    state.append(False)

                if  home_agent == self._ip3:
                    print("\nMobile Node received registration reply with the correct Home Agent IP address %s as expected\n" % home_agent)
                    state.append(True)
                else:
                    print("\nRegistration reply message is sent to the Mobile Node with the wrong Home Agent IP %s, Not the expected address %s -- Test Failed\n" % (home_agent, self._ip3))
                    state.append(False)


        except Exception as err:
            print("Failed to read packet with error %s" % err)
            state.append(False)
        
        return all(state) if state else False

    def run_agent_advert(self):

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
        
        return True


    def capture_packet(self):

        print("\nCapturing wireshark pcap packet")

        vm_user = "%s@%s" % (self._user_name, self._ip2)

        try:
            ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  tcpdump -i enp0s3 src 192.168.0.34 and port 434 -c 1 -w fa_reg_rep.pcap\n" % self._pwd],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)

            ma_process.communicate(timeout=100)
            ma_process.kill()

        except Exception as err:
             print("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self._ip2, err))
             return False
        
        print("\nEnd of capturing wireshark pcap packet")

        return True

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

        vm1_user = "%s@%s" % (self._user_name, self._ip1)
        vm1_process = subprocess.Popen(['ssh','-tt', vm1_user, "echo '%s' | sudo -S  reboot\n" % self._pwd],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)

        vm2_user = "%s@%s" % (self._user_name, self._ip2)
        vm2_process = subprocess.Popen(['ssh','-tt', vm2_user, "echo '%s' | sudo -S  reboot\n" % self._pwd],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)


        vm3_user = "%s@%s" % (self._user_name, self._ip3)
        vm3_process = subprocess.Popen(['ssh','-tt', vm3_user, "echo '%s' | sudo -S  reboot\n" % self._pwd],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)


        vm1_process.communicate()
        vm2_process.communicate()
        vm3_process.communicate()


        vm1_process.kill()
        vm2_process.kill()
        vm3_process.kill()

        print("Wait 120s for VMs to reboot")
        time.sleep(120)
        print("VMs are fully rebooted")

        return True
    
ha_reg_req().step_1()
ha_reg_req().step_2()






 












