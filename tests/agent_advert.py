
import subprocess
import re
from subprocess import PIPE
import pyshark
import os
import time

class net_scan():

    def __init__(self):

        self._pwd = "admin"
        self._ip1 = "admin@172.20.10.14"
        self._ip2 = "admin@172.20.10.5"
        aa_process = None
        ma_process = None
 
    def step_1(self):


        print("\nRunning Agent Advertisement Packet\n")

        closed_port_list = list()
        result_list = list()


        cmd_1 = "./mip/src/mip -m"
        cmd_2 = "./mip/src/mip -r"


        try:


            aa_process = subprocess.Popen(['ssh','-tt', self._ip1],
                                    stdin=subprocess.PIPE, 
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
            print("\nRunning Agent ddddddd Packet\n")


        except Exception as err:
            self._test_reporting.add_actual_msg("Connecting to Foriegn Agent VM with IP %s failed with error %s" % (self._ip1, err))
            return False

        try:
            ma_process = subprocess.Popen(['ssh','-tt', self._ip2],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                                bufsize=0)
            print("\nRunning Agent zzzz Packet\n")

        except Exception as err:
            self._test_reporting.add_actual_msg("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self._ip2, err))
            return False
    
        aa_process.stdin.write("echo 'admin' | sudo -S  ./mip/src/mip -m\n")

        time.sleep(5)

        ma_process.stdin.write("echo 'admin' | sudo -S  ./mip/src/mip -r\n")

        ma_process.stdin.write("uptime\n")
        time.sleep(30)



        state = self.check_packet_header(aa_process)

        self.clean_up(ma_process, aa_process)

        return state


    def check_packet_header(self, aa_process):
        """
        Check IP packet header
        """
        time.sleep(10)
        state = list()
        # waiting for test center to start


        path_capture_file = self._environment.get_project_folder()
        path_capture_file = '~/mip/tests/Results'

    #    self.__nodeA.get_linux_shell().send_cmd(["tcpdump -i tdma0.1 -c 1 -w p2ptcpdumpfile.pcap"])
        ma_process.stdin.write("echo 'admin' | sudo -S  tcpdump -i enp0s3 -c 1 -w agent_adv.pcap\n")
        # get local copy of dumpfile.pcap


        ma_process.get_scp().scp_get(remotefile="agent_adv.pcap", localpath=path_capture_file)

        # remove temporary dumpfile.pcap on linux machine
        ma_process.stdin.write("rm agent_adv.pcap\n")



        # read pcap file and read the tos vamolue
        pcap_file = pyshark.FileCapture(os.path.join(self._environment.get_project_folder(), 'p2ptcpdumpfile.pcap'))

        # try:
        #     for packet in pcap_file:
        #         tos_hex_value = int(packet.layers[1].dsfield, 16)
        #         gre_key_value = int(packet.layers[2].key, 16)
        #
        #         if int(tos_hex_value) == self.__dscp_service_value_list[self.__dscp_service]:
        #
        #             if gre_key_value == self.__tun1_key:
        #                 print("\nAgent advert message is sent to all multicats IP address and it is received b Mobile Node\n")
        #                 state.append(True)
        #             else:
        #                 print("\nAgent advert message is Not sent to all multicats IP address\n")
        #
        #                 state.append(False)
        #
        #             if gre_key_value == self.__tun1_key:
        #                 print("\nAgent advert message is sent to all multicats IP address with the right Code\n")
        #                 state.append(True)
        #             else:
        #                 print("\nAgent advert message is Not sent to all multicats IP address\n")
        #
        #                 state.append(False)
        #
        #             if gre_key_value == self.__tun1_key:
        #                 print("\nAgent advert message is sent to all multicats IP address with the right Typse\n")
        #                 state.append(True)
        #             else:
        #                 print("\nAgent advert message is Not sent to all multicats IP address\n")
        #
        #                 state.append(False)
        #
        #
        #         else:
        #             print("Failed to interpret captured packet on Global VRF")
        #             state.append(True)
        #
        #
        # except Exception, err:
        #     print("Failed to  captured packet with error %s" % err)
        #
        #     state.append(False)
        #
        # return all(state) if state else False

        return True


    def clean_up(ma_process, aa_process):
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





 












