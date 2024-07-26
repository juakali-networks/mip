
import subprocess
import re
from subprocess import PIPE
import pyshark
import os
import time
import paramiko
from scp.scp import SCPClient

class setup_vm():

    def __init__(self):

        # Configs. Change your settings here
        self._pwd = "lubuntu"
        self._user_name = "lubuntu"

 
 
    def step_1(self, vm_ip):


        print("\nConnecting to Virtual Machine with IP address %s\n" % vm_ip)
       
        vm_user = "%s@%s" % (self._user_name, vm_ip)

        cmd = "echo '%s' | sudo -S rm -r mip" % self._pwd
        vm_process = subprocess.Popen(['ssh','-tt', vm_user, "%s" % cmd],
                                    stdin=subprocess.PIPE, 
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
        results_output, results_error = vm_process.communicate()
        results_output_bytes = bytes(results_output, 'ascii')    
        print(results_output_bytes)  
        vm_process.kill()

        cmd = "git clone https://github.com/juakali-networks/mip.git"
        vm_process = subprocess.Popen(['ssh','-tt', vm_user, "%s" % cmd],
                                    stdin=subprocess.PIPE, 
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
        results_output, results_error = vm_process.communicate()
        results_output_bytes = bytes(results_output, 'ascii')    
        print(results_output_bytes)  
        vm_process.kill()

        '''
        cmd = "rm mip/src/mip"
        vm_process = subprocess.Popen(['ssh','-tt', vm_user, "%s" % cmd],
                                    stdin=subprocess.PIPE, 
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
        results_output, results_error = vm_process.communicate()
        results_output_bytes = bytes(results_output, 'ascii')    
        print(results_output_bytes) 
        vm_process.kill()
 
        cmd = "rm mip/src/obj/mip.o"     
        vm_process = subprocess.Popen(['ssh','-tt', vm_user, "%s" % cmd],
                                    stdin=subprocess.PIPE, 
                                    stdout = subprocess.PIPE,
                                    universal_newlines=True,
                                bufsize=0)
        results_output, results_error = vm_process.communicate()
        results_output_bytes = bytes(results_output, 'ascii')    
        print(results_output_bytes)  
        vm_process.kill()
  
        cmd = "cd mip/src && make clean"    
        vm_process = subprocess.Popen(['ssh','-tt', vm_user, "%s" % cmd],
                                     stdin=subprocess.PIPE, 
                                     stdout = subprocess.PIPE,
                                     universal_newlines=True,
                                 bufsize=0)
        results_output, results_error = vm_process.communicate()
        results_output_bytes = bytes(results_output, 'ascii')    
        print(results_output_bytes)
        vm_process.kill()
        '''
        
        cmd = "cd mip/src && make"    
        vm_process = subprocess.Popen(['ssh','-tt', vm_user, "%s" % cmd],
                                   stdin=subprocess.PIPE, 
                                   stdout = subprocess.PIPE,
                                   universal_newlines=True,
                               bufsize=0)
        results_output, results_error = vm_process.communicate()
        results_output_bytes = bytes(results_output, 'ascii')[0]
        print(results_output_bytes)
        vm_process.kill()

        return True

ip1 = "192.168.0.33"
ip2 = "192.168.0.240"
ip3 = "192.168.0.85"

setup_vm().step_1(ip1)
setup_vm().step_1(ip2)
setup_vm().step_1(ip3)


    
            













 












