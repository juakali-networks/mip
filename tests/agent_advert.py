
import subprocess
import re
from subprocess import PIPE
import pyshark
import os
import time
import paramiko
from scp.scp import SCPClient
# from scp.SCPClient import SCPClient

class net_scan():

    def __init__(self):

        self._pwd = "admin"
        self._ip1 = "admin@172.20.10.14"
        self._ip2 = "admin@172.20.10.5"
        self._all_host_mcast_addr = "224.0.0.1"
        self._agent_advert_type = "9"
        self._agent_advert_code = "16"
        aa_process = None
        ma_process = None
 
    def step_1(self):

        closed_port_list = list()
        result_list = list()

        cmd_1 = "./mip/src/mip -m"
        cmd_2 = "./mip/src/mip -r"


        print("\nForeign Agent sending Agent Advertisement multicast packet\n")
        
        try:


            aa_process = subprocess.Popen(['ssh','-tt', self._ip1],
                                    stdin=subprocess.PIPE, 
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)


        except Exception as err:
            self._test_reporting.add_actual_msg("Connecting to Foriegn Agent VM with IP %s failed with error %s" % (self._ip1, err))
            return False

        print("Mobile Node sending Registration Reply Packet to Foreign Adent\n")


        try:
            ma_process = subprocess.Popen(['ssh','-tt', self._ip2],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                                bufsize=0)

        except Exception as err:
            self._test_reporting.add_actual_msg("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self._ip2, err))
            return False
    
        aa_process.stdin.write("echo 'admin' | sudo -S  ./mip/src/mip -m\n")

        time.sleep(5)
        ma_process.stdin.write("echo 'admin' | sudo -S  ./mip/src/mip -r\n")

        ma_process.stdin.write("uptime\n")
        time.sleep(30)



        state = self.check_packet_header(ma_process)

        self.clean_up(ma_process, aa_process)

        return state


    def check_packet_header(self, ma_process):
        """
        Check IP packet header
        """
        state = list()

        local_path = '/home/peter/mip/tests/Results'
        ma_process.stdin.write("echo 'admin' | sudo -S  tcpdump -i enp0s3 -c 1 -w agent_adv.pcap")

        remote_path = 'agent_adv.pcap'
        ssh = self.createSSHClient("172.20.10.5", 22, "admin", "admin")
        scp = SCPClient(ssh.get_transport())
        scp.get(remote_path=remote_path, local_path=local_path)
        ma_process.stdin.write("recho 'admin' | sudo -S m agent_adv.pcap\n")

        scp.close()

        # read pcap file and read packet fields
        pcap_file = pyshark.FileCapture('/home/peter/mip/tests/Results/agent_adv.pcap')

        try:
            for packet in pcap_file:

                tos_hex_value = int(packet.layers[1].dsfield, 16)
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
        #
        #    state.append(False)
        #
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
            ma_process.kill()
        except Exception as err:
            print("Failed to kill process  with error %s" % err)


        try:
            ma_process.kill()
        except Exception as err:
            print("Failed to kill process  with error %s" % err)

        return True

net_scan().step_1()





 












