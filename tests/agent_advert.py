
import subprocess
import re
from subprocess import PIPE
# import pyshark
import os

class net_scan():

    def __init__(self):

        self._pwd = "admin"
        self.__ip1 = "admin@172.20.10.14"
        self.__ip2 = "admin@172.20.10.5"
        aa_process = None
        ma_process = None
 
    def step_1(self):

        #try:
        #    self._fa = Ssh(host=self.__ip1, port=22, user="admin", passwd="admin")
        #except Exception as err:
        #    self._test_reporting.add_actual_msg("Connecting to Foreign Agent VM with IP %s failed with error %s" % (self.__ip1, err))
        #    return False

        #try:
        #    self._ma = Ssh(host=self.__ip2, port=22, user="admin", passwd="admin")
        #except Exception as err:
        #    self._test_reporting.add_actual_msg("Connecting to Mobile Agent VM with IP %s failed with error %s" % (self.__ip1, err))
        #    return False



            print("\nRunning Agent Advertisement Packet\n")

            closed_port_list = list()
            result_list = list()


            cmd_1 = "./mip/src/mip -m"
            cmd_2 = "./mip/src/mip -r"





            aa_process = subprocess.Popen(['ssh','-tt', self.__ip1],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                                bufsize=0)

            ma_process = subprocess.Popen(['ssh','-tt', self.__ip2],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                                bufsize=0)
    
            aa_process.stdin.write("echo 'admin' | sudo -S  ./mip/src/mip -m\n")
            aa_process.stdin.write("ls .\n")
            aa_process.stdin.write("echo END\n")
            aa_process.stdin.write("uptime\n")
            aa_process.stdin.write("logout\n")
            aa_process.stdin.close()

            ma_process.stdin.write("echo 'admin' | sudo -S  ./mip/src/mip -r\n")
            ma_process.stdin.write("ls .\n")
            ma_process.stdin.write("echo END\n")
            ma_process.stdin.write("uptime\n")
            ma_process.stdin.write("logout\n")
            ma_process.stdin.close()

            for line in aa_process.stdout:
                if line == "END\n":
                    break
                print(line,end="")

            #to catch the lines up to logout
            for line in  aa_process.stdout: 
                print(line,end="")

            for line in ma_process.stdout:
                if line == "END\n":
                    break
                print(line,end="")

            #to catch the lines up to logout
            for line in  ma_process.stdout: 
                print(line,end="")
        
            aa_process.kill()
            ma_process.kill()

net_scan().step_1()





 












