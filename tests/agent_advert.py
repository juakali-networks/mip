
import subprocess
import re
from subprocess import PIPE
import pyshark
import os
import time
import paramiko
from scp.scp import SCPClient
# from scp.SCPClient import SCPClient

class agent_adv():

    def __init__(self):

        # Configs. Change your settings here
        self._user_name = "lubuntu"
        self._pwd = "lubuntu"
        self._ip1 = "192.168.0.34"
        self._ip2 = "192.168.0.240"
        self._all_host_mcast_addr = "224.0.0.1"
        self._agent_advert_type = "9"
        self._agent_advert_code = "16"
        self._file = 'agent_adv.pcap'
        self._local_path = '/home/dancer/mip/tests/Results'

 
    def step_1(self):

        subprocess.run(["rm Results/agent_adv.pcap"], shell=True, capture_output=False)

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

        print("Mobile Node sending Registration Reply Packet to Foreign Adent\n")

        time.sleep(5)

        vm_user = "%s@%s" % (self._user_name, self._ip2)

        try:
            ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo %s | sudo -S  ./mip/src/mip -r" % self._pwd],
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

        self.clean_up()

        return state


    def check_packet_header(self):
        """
        Check IP packet header
        """
        state = list()

        print("\nCapturing wireshark pcap packet")

        vm_user = "%s@%s" % (self._user_name, self._ip2)

        try:
            ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo '%s' | sudo -S  tcpdump -i enp0s3 icmp -c 1 -w agent_adv.pcap\n" % self._pwd],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
            ma_process.communicate()
            ma_process.kill()

        except Exception as err:
             print("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self._ip2, err))
             return False
    
        print("\nEnd of capturing wireshark pcap packet")

        # username = "%s" % self._pwd
        ssh = self.createSSHClient(self._ip2, 22, self._pwd, self._pwd)
        scp = SCPClient(ssh.get_transport())
        scp.get(remote_path=self._file, local_path=self._local_path)
        scp.close()
    
        vm_user = "%s@%s" % (self._user_name, self._ip2)

        ma_process = subprocess.Popen(['ssh','-tt', vm_user, "echo %s | sudo -S rm agent_adv.pcap\n" % self._pwd],
                                    stdin=subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                    bufsize=0)
        ma_process.communicate()

        ma_process.kill()


        # read pcap file and read packet fields
        pcap_file = pyshark.FileCapture('/home/dancer/mip/tests/Results/agent_adv.pcap')

        try:
            for packet in pcap_file:

           #     tos_hex_value = int(packet.layers[1].dsfield, 16)
                dst_addr = packet.layers[1].dst
                icmp_type = packet.layers[2].type
                icmp_code = packet.layers[2].code


                if dst_addr == self._all_host_mcast_addr:
                    print("\nForeign agent sent Agent Advert message to Mobile Node on all host multicast IP address %s as expected\n" % dst_addr)
                    state.append(True)
                else:
                    print("\nAgent advert message is Not sent to all host multicast IP address %s but to destination address %s\n" % (self._all_host_mcast_addr, dst_addr))
                    state.append(False)
                if icmp_type == self._agent_advert_type:
                    print("\nAgent Advert message is sent with correct ICMP type number %s\n" % icmp_type)
                    state.append(True)
                else:
                    print("\ngent Advert message is sent with wrong ICMP type number %s and not type number %s\n" % (self._agent_advert_type, icmp_type))
                    state.append(False)


                if icmp_code == self._agent_advert_code:
                    print("\nAgent Advert message is sent with correct ICMP code %s\n" % icmp_code)
                    state.append(True)
                else:
                    print("\ngent Advert message is sent with wrong ICMP code %s and not code %s\n" % (self._agent_advert_type, icmp_type))
                    state.append(False)


        except Exception as err:
            print("Failed to  captured packet with error %s" % err)
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

        vm1_process.communicate()
        vm2_process.communicate()

        vm1_process.kill()
        vm2_process.kill()

        print("Wait 60s for VMs to reboot")
        time.sleep(60)
        print("VMs are fully rebooted")

        return True


agent_adv().step_1()





 












