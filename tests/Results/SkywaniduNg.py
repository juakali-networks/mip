"""
@license:
This document is the property of ND SatCom GmbH who own the copyright
therein. The information in this document must not be copied, reprinted
or reproduced in any material form either wholly or in part nor must the
contents of the document or any method or technique available therefrom
be disclosed to any third party.
@copyright: ND SatCom GmbH - Quality Assurance, Verification
@author: Alexander Kress
@date: 28.03.2013
@collaboration: Mostafa Mir
"""

import ConfigParser
import os
import hashlib
import inspect
import time
import re
import shutil
from datetime import datetime as dt
from ndsatcom.products.skywanng.fpga.FPGAManager import FPGAManager
from ndsatcom.common.netconf.Netconf import Netconf
from ndsatcom.common.snmp.Snmp import Snmp
from ndsatcom.common.ssh.Ssh import Ssh
from ndsatcom.common.ssh.Scp import Scp
from ndsatcom.common.ssh.Sftp import Sftp
from ndsatcom.common.ping.ping import Ping
from ndsatcom.products.skywanng.webbrowser.WebBrowser import WebBrowser
from ndsatcom.common.netconf.NetconfHiSpeed import NetconfHiSpeed


### GLOBAL DEFINES

### CLASS
class SkywaniduNg(object):
    """
    Represents the SKYWAN NG device
    """

    def __init__(self, skywanidu_ip, device_id, dvb_hw_version='None'):
        """
        Create a new instance of the IDU specified by the given IP address

        @param skywanidu_ip: IP address of the Skywanidu
        @type  skywanidu_ip: String

        @param device_id: Device ID of the Skywanidu
        @type  device_id: String
        """
        self.__device = device_id
        self.__dvb_hw_version = dvb_hw_version

        # config from idu
        self.idu_config = None

        # create instance of Config Parser
        self.__config = ConfigParser.ConfigParser()

        # get the local path
        self.__base_path = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

        # get path of config.cfg file
        config_file = os.path.join(self.__base_path, "config", "productsetup.cfg")

        # read content of config file
        self.__config.read(config_file)

        self.__skywanidu_ip = skywanidu_ip
        if skywanidu_ip is None:
            target_ip_network = "172.24.136."
            target_ip_host = self.__device.split('_')[-1]

            self.__skywanidu_ip = target_ip_network + target_ip_host

        # create Netconf instance
        ncclient = True
        if ncclient:
            # use NetConf client 'ncclient'
            self.__netconf = Netconf(host=self.__skywanidu_ip, port=self.__config.get(self.__device, "NETCONF_Port"), user=self.__config.get(self.__device, "NETCONF_User"), passwd=self.__config.get(self.__device, "NETCONF_Password"), protocol=self.__config.get(self.__device, "NETCONF_Protocol"))
        # else:
        #     # use NetConf client 'netconf-console'
        #     self.__netconf = NetconfConsole(host=self.__skywanidu_ip, port=self.__config.get(self.__device, "NETCONF_Port"), user=self.__config.get(self.__device, "NETCONF_User"), passwd=self.__config.get(self.__device, "NETCONF_Password"))

        # Declare NetconfHispeed placeholder as late-initialization, initialized at first use
        self.__netconf_hispeed = None

        # create SNMP v2 instance
        self.__snmp_v2 = Snmp(host=self.__skywanidu_ip, port=self.__config.get(self.__device, "SNMP_Port"), read_community=self.__config.get(self.__device, "SNMP_Read_Community"), snmp_version=2)

        # create SNMP v3 instance
        self.__snmp_v3 = Snmp(host=self.__skywanidu_ip, port=self.__config.get(self.__device, "SNMP_Port"), read_community=self.__config.get(self.__device, "SNMP_Read_Community"), snmp_version=3, auth_user=self.__config.get(self.__device, "SNMP_Auth_User"), auth_key=None, priv_key=None)

        # check WebUI port and change http or https
        if self.__config.get(self.__device, "WebUI_Port") == '80':
            prefix = 'http://'
        elif self.__config.get(self.__device, "WebUI_Port") == '443':
            prefix = 'https://'
        else:
            raise Exception("The WebUI port '%s' is not supported.")

        # create WebBrowser instance
        self.__webbrowser_ie = WebBrowser('Internet Explorer', prefix + self.get_ip(), user_name=self.__config.get(self.__device, "WebUI_User"), password=self.__config.get(self.__device, "WebUI_Password"))
        self.__webbrowser_ff = WebBrowser('Firefox', prefix + self.get_ip(), user_name=self.__config.get(self.__device, "WebUI_User"), password=self.__config.get(self.__device, "WebUI_Password"))

        # create SSH instances
        self.__linux_shell = Ssh(host=self.__skywanidu_ip, port=int(self.__config.get(self.__device, "SSH_Port")), user=self.__config.get(self.__device, "SSH_User"), passwd=self.__config.get(self.__device, "SSH_Password"))
        self.__metacli = Ssh(host=self.__skywanidu_ip, port=int(self.__config.get(self.__device, "MetaCLI_Port")), user=self.__config.get(self.__device, "MetaCLI_User"), passwd=self.__config.get(self.__device, "MetaCLI_Password"))
        self.__scp = Scp(host=self.__skywanidu_ip, port=int(self.__config.get(self.__device, "SSH_Port")), user=self.__config.get(self.__device, "SSH_User"), passwd=self.__config.get(self.__device, "SSH_Password"))
        self.__sftp = Sftp(host=self.__skywanidu_ip, port=int(self.__config.get(self.__device, "SSH_Port")), user=self.__config.get(self.__device, "SSH_User"), passwd=self.__config.get(self.__device, "SSH_Password"))
        self.__fpga = FPGAManager(host=self.__skywanidu_ip)

        self.__ping = Ping(target=self.__skywanidu_ip)
        self.__serial_number = None
        self.__rx_channel = None
        self.__device_sll = None
        self.__tdma_network_nodes = None

    def factory_default_config(self, source=None):
        """
        Set IDU config to factory default config

        @param source: running or candidate
        @type  source: String
        """
        # # get next index for vrf
        # next_index = int(self.__netconf.get_value('vrf-config/next-index')[-1]) + 4

        file_path = os.path.join(self.__base_path, 'snippets', 'clean_config.xml')

        revison_str = self.__netconf.get_value('confd-state/loaded-data-models/data-model[name="node"]/revision')[-1]
        revision = dt.strptime(revison_str, "%Y-%m-%d")
        node_root = dt.strptime("2022-03-07", "%Y-%m-%d")

        if revision < node_root:
            str_node_root = """
                            <root-account>
                              <root-passwd-enabled>true</root-passwd-enabled>
                              <root-password>$1$.sDZOHuZ$lONr7vRhrLCvjZ0VaU9Ti0</root-password>
                            </root-account>"""
            str_aaa_root = ""
        else:
            str_node_root = ""
            str_aaa_root = """
                           <user>
                             <name>root</name>
                             <uid>0</uid>
                             <gid>0</gid>
                             <password>$1$ILOlGFp.$.H3zuclbplhw032Yv.41t/</password>
                             <ssh_keydir>/home/root/.ssh</ssh_keydir>
                             <homedir>/home/root</homedir>
                             <ssh-login-allowed xmlns="http://tail-f.com/ns/example/nd-aaa">true</ssh-login-allowed>
                            </user>
                """
        snippet = self.__netconf.get_xml_snippet_from_file(file_path, [str_node_root, str_aaa_root])
        self.__netconf.copy_config(config_snippet=snippet, source=source, wait_time=600)

        print "Factory default configuration successfully copied to '%s' datastore." % source

    def delete_configuration(self):
        file_path = os.path.join(self.__base_path, 'snippets', 'delete_config.xml')
        self.__netconf.edit_value(file_name=file_path, parms=[], wait_time=180)

    def counter_reset(self):
        #reset switch statistics until implemented in software
        self.get_linux_shell().send_cmd(["/nds/sys/switch w global 1d 9c00"])
        file_path = os.path.join(self.__base_path, 'snippets', 'counter_reset.xml')
        self.__netconf.action(file_path)

    def get_serial_number(self):
        if not self.__serial_number:
            self.__serial_number = self.__netconf.get_value('node/node-serial-number')[-1]
        return self.__serial_number

    def get_license_key_value(self):
        license_key = self.__config.get(self.__device, "license")
        return license_key

    def get_default_vlan_id(self):
        default_vlan_id = int(self.__config.get(self.__device, "Default_Vlan_ID"))
        return default_vlan_id

    def get_default_switch_port(self):
        default_switch_port = int(self.__config.get(self.__device, "Default_Switch_Port"))
        return default_switch_port

    def get_default_switch_type(self):
        default_switch_type = self.__config.get(self.__device, "Default_Switch_Type")
        return default_switch_type

    def get_second_switch_port(self):
        second_switch_port = int(self.__config.get(self.__device, "Second_Switch_Port"))
        return second_switch_port

    def get_device_sll(self):
        # returns device sll address from tdma dataprovider
        if not self.__device_sll or self.__device_sll == 0:
            try:
                self.__device_sll = 0
                self.__device_sll = int(self.__netconf.get_value('tdma/channel-access/sll-address')[-1])
            except Exception as err:
                self.__device_sll = 0
        return self.__device_sll
    # end get_device_sll(..)

    def get_rx_channel(self):
        if not self.__rx_channel:
            cmd = "tdma/master/network-nodes[network-access-control-serial-number/text()='%s']/rx-reference-channel" % self.get_serial_number()
            self.__rx_channel = self.__netconf.get_config_value(cmd, source='running')[-1]
        return self.__rx_channel

    def get_tdma_network_nodes(self):
        if not self.__tdma_network_nodes:
            self.__tdma_network_nodes = {}

            node_list = self.__netconf.get_value('tdma/master/network-nodes/rx-reference-channel')
            # format is [ SLL Serial RX-CHANNEL ... ]
            # so it is always a 3 tuple
            entries = len(node_list)
            if (entries % 3) != 0:
                raise Exception("ERROR: The given nodelist is not in the correct format %s " % node_list)
            for i in range(entries / 3):
                sll = int(node_list[i * 3 + 0])
                serial = str(node_list[i * 3 + 1])
                rx_ch = int(node_list[i * 3 + 2])

                if sll not in self.__tdma_network_nodes:
                    self.__tdma_network_nodes[sll] = [serial]
                else:
                    self.__tdma_network_nodes[sll].append(serial)

            print self.__tdma_network_nodes

        return self.__tdma_network_nodes

    def get_tdma_role(self):
        try:
            xpath = "tdma/channel-access/master-state"
            return self.__netconf.get_value(xpath)[-1]
        except Exception, err:
            return 'unknown (error: %s)' % err

    def get_configured_tdma_master_state(self):
        try:
            xpath = "tdma/station/master-state"
            return self.__netconf.get_value(xpath)[-1]
        except Exception, err:
            return 'unknown (error: %s)' % err

    def ping_remote_via_linux(self, destination, interface='tdma0.1', retries=10, vrf='global', num_of_pings=1):
        poll_interval = 10
        interface_name = interface.split('.')[0]
        unit = interface.split('.')[1]
        for run in range(1, retries + 1):
            result = self.get_linux_shell().send_cmd(['chvrf %s ping -c %s %s' % (vrf, num_of_pings, destination.get_netconf().get_value('network/interfaces/interface[name/text()="%s"]/unit[name/text()=%s]/family/inet/address/name' % (interface_name, unit))[-1])])
            if '0% packet loss' in result and '%s received' % num_of_pings in result:
                msg = "VRF %s: Ping to remote was successful after %s iteration%s.\n" % (vrf, run, 's' if run > 1 else '')
                return {'state': True, 'msg': msg}
            else:
                time.sleep(poll_interval)
        else:
            msg = "VRF %s: All the pings failed after %s seconds -> Step failed\n" % (vrf, retries*poll_interval)
            return {'state': False, 'msg': msg}

    def check_arp_entry(self, arp_entry, timeout=120, poll_interval=5, vrf='global'):
        """
        Check for proper ARP resolution
        """
        timecount = 0
        regex_mac = '([a-fA-F0-9]{2}[:|\-]?){6}'

        while timecount < timeout:
            rtn_value = self.get_linux_shell().send_cmd(["chvrf %s arp | grep '%s'" % (vrf, arp_entry)]).strip()
            if arp_entry in rtn_value and re.compile(regex_mac).search(rtn_value):
                return True
            else:
                time.sleep(poll_interval)
                timecount += poll_interval

        return False

    def reboot_linux(self, wait_for_reboot=True):
        """
        Reboot target linux system
        """
        # reboot target
        print "Rebooting IDU..."
        self.log_syslog(msg='reboot requested by autotest', bookmark=True)
        # delete redundancy boot log counter
        self.get_linux_shell().send_cmd(['rm /nvram/boot_counter.log'])
        # reboot via CLI command
        self.get_linux_shell().send_cmd(['reboot'])
        # wait after reboot
        if wait_for_reboot:
            print "Waiting for IDU reboot..."
            wait_time = 260
            time.sleep(wait_time)
            return self.check_accessible(waited=wait_time)
        else:
            return True

    def check_accessible(self, waited=0):
        """
        Check IDU accessibility

        @param waited: Offset of boot_time value
        @type  waited: Integer
        """
        # ping for max. 5 mins
        time_out = 300
        poll_interval = 10
        for iteration in range(time_out/poll_interval):
            if self.__ping.ping():
                boot_time = (iteration * poll_interval) + waited
                print "%s reachable after %s seconds" % (self.get_device_id(), boot_time)
                return self.check_runlevel_forwarding(boot_time)
            else:
                time.sleep(poll_interval)
        else:
            print "%s not reachable after %s seconds" % (self.get_device_id(), (time_out + waited))
            return False

    def check_if_tdma_is_ready(self):
        """
        Check status of runlevel-forwarding-stable
        """
        # max. 5 mins
        time_out = 300
        poll_interval = 10
        for iteration in range(time_out/poll_interval):
            time.sleep(poll_interval)
            try:
                result = self.get_metacli().send_cmd(['show tdma tdmacalc tdma-calc-params tdma-calculation-status'])
                if "tdma tdmacalc tdma-calc-params tdma-calculation-status" in result:
                    print "%s in 'TDMA ready' state" % self.get_device_id()
                    return True
            except Exception as err:
                print "Exception in check_if_tdma_is_ready: %s" % err
        else:
            print "%s is not in 'TDMA ready' state after time out." % self.get_device_id()
            return False

    def check_runlevel_forwarding(self, waited=0):
        """
        Check status of runlevel-forwarding-stable
        """
        # max. 5 mins
        time_out = 300
        poll_interval = 10
        for iteration in range(time_out/poll_interval):
            time.sleep(poll_interval)
            try:
                result = self.get_metacli().send_cmd(['show node run-level'])
                runtime = (iteration * poll_interval) + waited
                if "node run-level run-level-forwarding-stable" in result:
                    print "%s in 'run-level-forwarding-stable' state after %s seconds" % (self.get_device_id(), runtime)
                    return True
            except Exception as err:
                print "Exception in check_runlevel_forwarding: %s" % err
        else:
            print "%s is not in 'run-level-forwarding-stable' state after time out %s second." % (self.get_device_id(), (time_out + waited))
            return False

    def reboot_idu_check_run_level_forwarding(self):
        """
        Reboot target skywan idu and wait to get run-level-forwarding-stable
        The time_out is set to 300 second
        """
        print "Rebooting %s and waiting to get run-level-forwarding-stable ..." % self.get_device_id()
        self.log_syslog(msg='reboot requested by autotest', bookmark=True)
        wait_time = 120
        # delete redundancy boot log counter
        self.get_linux_shell().send_cmd(['rm /nvram/boot_counter.log'])
        # reboot via CLI command
        self.get_metacli().send_cmd(['node reset'])

        time.sleep(wait_time)

        return self.check_accessible(waited=wait_time)

    def reboot_idu_check_run_level_forwarding_and_tdma(self):
        """
        Reboot target skywan idu and wait to get run-level-forwarding-stable
        The time_out is set to 300 second
        """
        print "Rebooting %s and waiting to get run-level-forwarding-stable ..." % self.get_device_id()
        self.log_syslog(msg='reboot requested by autotest', bookmark=True)
        wait_time = 120
        # delete redundancy boot log counter
        self.get_linux_shell().send_cmd(['rm /nvram/boot_counter.log'])
        # reboot via CLI command
        self.getO-etacli(+.send_cmd(['.ode reset'])

      $ ´yme.sleep(wait_|ime)

"   !   if self.chesk_A#Cessible)waitgd=Wait_time):
           !beturn self.check_if_tl}a_is_ready()
        rettrn False

    def factory_beset_check_pun_level_fobwardin'(self):
        """J  "     Facvoby reset skywan )du!and wait to get run-level-forwardiog-stable
   " (( The time_out0is setto 300 secn$
        "&
        ðrint "Pårforming factory reseô %s and ÷aiting to get run-level-forgarding-stable *.." % 3elf/get_device_id )
        self,log_syslow(msg='factory+reset afD reboot requesteD by autotest', fookmark=True)
        wait_time =(120      $ try:
            action_output = self.get_metaclm(­.send_cmd(['conf t', 'node gagtory_reset'])
          " if "OK" hn aktion_output:
  0  (       `  print("es: Performed factory veset:!!S ait for reboot." % (selfget_device_id*)< actio._output))
            else:    !           print("%s: Performed factory ruset and resulted in failure: 's -)> step failed" % (self.ged_fevike_id(), action_outpud))
      ! exce0t Ex#eption as err:            print("Exception for s: %s " % ¨self.get_devicd_id(), err))

     0  time.sleep*wait_time)

        2eturn self.check_accessibhe(waited=wait_time)
	
    def reboOt_idu_sheck_phngable(self):
        """
        Reboot tarcet skùwcn8idu and wait to(gåt pingable
        The time_out is set to 300 second
        """
        print "Rebooting %s and uaiting maxieum 301 secondhto ggt pingab,e .*." % self.get[levice_id()
     !! self,log_syslog(msg='reboot requested by autotest7, bomjmark-Urue)
    0`  wait_time = 60
        Self.gut_linux_shell(©send_cmd(['rm /nvra}/boot^counter.log'])
        self.getlinux_shell().sent_cmd(['reboot'])
        time.qmeep(wait_time)

        boot_time = wakt]time     !  for poll in range(300):
     !      boot_time += 1

           (if self.__pinç.ping():
                print0"%s pinoable a.tmr %s seconds" % self.get_deöice_id(), boot_tima)
!    (          break
            else:
 (    !      $  # max. 5`mins
          $     if boot_time > 380:
       !        "  print "%s not0pingable after %s seconds" % (self.get_device_id(), boot_time)                    return False* $              else:
    0 (        $ $  tmme.slee`*1)

    def get_netconf_arg}ments(self):
        """
   `   "Returns IDT Netconfie!Cvedeftials
     "  """
        return sgìf._device, self.__skywafidu_ip, self*__config,get(selg&__device- "NETCONF_Popt"), self.__config.get(self/__device, "NETCONN_Ucer"), sel&.__cOnfig.ggt(self.__defiáe, "NETCONF]Passwoúd"), self.__conbig.get(self.__device, "NDTCONÆ_Protocl")

    def get_mdtacli_argUmentw(self©:
`     ! """
  0    $Retur~s IDU CLA Credentials
     0  """
        retõrn self._[device, self.__sëywanmdu_ip, self.__config.get(sel&.__device, "MetaCLI_Port"i, óelf.__config.gut(self.__device, "MetaCLI_User")$ celf.__confùg.get(self.__device, "MetaCLI_Password")

    def get_piNg(self):
$   `   """
  (     Get instance of Pi~w class        """
        return sdlf.__ping
J   def get_md5(smlf, file_namg):
 `      """
        Compute me5 hash of the specified fileM

       @param file_name:!Input file Fame
        `|ype  file_name: Stryng
        """
        md5_hash = hashlib.new('mD5')
        with opeN(file]name, "rb") as filehaodle:-
            data = fileiandlu.read()
           `md5_hash.update(deta)
        return md4_hesh.hexdigeSt()
    def get_idu_logs(self, local_path):
        """
 `     0Get IDU Log FilesM

        @param local_path: Locel path to store log files
  !0    @vipe  local_path: String*        """
        if not os.path.exists(local_path):
            os.makedirs(local_path)

        self.__scp.scp_çet(reMotefile='/nfram/sys.loç', losalpath9local_path(
        trq:
 (          for n in$rance(1, 5):
                fileßname = "/tMp/sys.loç.%d""% n
$   "     $    03alf.__sbp.scp_get(remotefile=file_name¬ ìgãalpath<local_paôh)
 (      except Exception:
            pass

    def get_all_logq(se|f, ut_path):
        """
        Get IDU0Log files i.to one file

       0@param out_path: Local p`th to store log file on lostM
     "  @tyte  out_patl: String    !   ¢""
        thmespamp = dt.now()
   !0  (logsuffix = timestaip.strfvime('%y%m%dT%H%M%S')J        out]file = o3.pathjoin(out_pati,0"%sOsum_te3tpun_es.log" % (self.wet_d%vice_id(), logsuffih))
 $ 0    print`"baseclass::get_all_logs(..)*\r\n- all sysmogs of %s ave trancferred to %s:" % (self.get_device_id(), gut_file)
        files = self.get_sftp()nlisô_dip("/log")
!       äl_loes = []
 `      fob fnáme in files:
!         ! if 'sys.log' iN fname:
                ury:*       `            selb.get_scp,).scp_get("olog/%s" % fname, out_path)	
                    dl_logs.append(fneme)
 "              exceqt Excepdiol:
 `                  # ignore logs which ave not present
                    continue
"       # cncit fmles ijuo one Log
    "   with open)out_file, çwb') as lkgJ            for f in sorted(dl_logs, reverse=True):
        $       print "  mgrgyng %s...b % &
$               fale_p`tx"= os/padh.jgin(out_path, f)
                wIth open(file_path, 'rb7) es fd:
                    shu|il.copyfileobj(fd, |og)
      !         os.remove(file_path+

        ret}rn True
    # mnd get_aLl_logs(..+

    deg get_list_core_dumps(self):
        """
   `    Returns a!,ist of core-d}mPs
        :return: striNg
  !     """
       ,res = None
   )  4 for i!in 2ange(0, 5):
           !res = None
            try:
        !       res = self.get_lynux_sheln(),senä_cmd(['ls -l --full-time /defaulus/bore/'])J                return str(res)
      `(    except Exception as err:
                # wait 30 seconds to allgw IDU to turn raaghable again
         `      time.sleep(30)
  `     # enD tr9olkop
        return None
    # end def get_list_core_dueps(..)	

    deæ get_list_i$ußnogs(self):
        """      !Return a list of IDU`log fimes location
        """
        log_list = Z'/nvram/sùs.lof',
                    ]
    $   return log_list
    den get_fpge(selö):
        """
        et instaþ#e of FPGA class
        """
   `    return óelf._^fpga

(   äef eet_fetconf(self):
        """
 !      Get instance of Netconf claqs
        """
        reTurn$self.__netconfJ
    def get_netãonf_hispedd(self):
        """
        Get instance oæ hisPeed netconf communicataif!channel,
        :re|usn: NetconfHiSpeed, identical call-interface aw the regular!Netconf-clacs.
 "      :note:   Please consider using the .close(..) function of the returned NetconfHiSpeed as part of autotest-cleanup/-teardown,
                 to avoid implications caused by the Python' GC non-deterministic behaviour.
        """
        if self.__netconf_hispeed is None:
            self.__netconf_hispeed = NetconfHiSpeed()
            self.__netconf_hispeed.set_netconf_arguments(self.get_netconf_arguments())

        return self.__netconf_hispeed

    def get_snmp(self, version=2):
        """
        Get instance of SNMP class

        @param version: SNMP Version (2 or 3)
        @type  version: Integer
        """
        if version == 2:
            return self.__snmp_v2
        elif version == 3:
            return self.__snmp_v3
        else:
            raise Exception("ERROR: The given SNMP version '%s' is not supported" % version)

    def get_webbrowser(self, browser_type='Internet Explorer'):
        """
        Get instance of WebBrowser class

        @param browser_type: Browser type (Internet Explorer or Firefox)
        @type  browser_type: String
        """
        if browser_type == 'Internet Explorer':
            return self.__webbrowser_ie
        elif browser_type == 'Firefox':
            return self.__webbrowser_ff
        else:
            raise Exception("ERROR: The given browser name '%s' is not supported" % browser_type)

    def get_linux_shell(self):
        """
        Get instance of SSH Linux Shell class
        """
        return self.__linux_shell

    def!get_metacli(selg9z
        """
      " Gdt i.stance of(SKYWAN MetaCLI class
!       """
       $veturn self._íetacli

    def get_scp(self):
    "   """
    0   Get instance on0SCP class  "     """
        r$tubn!sel&.__scp

    den get_sftr({enf):
        """
   h    Get instance of SFDp class
        "¢"
        return selb.__sftp

  ` def"get_moxa_pOrt(semf):	
        """
    "   Fet uxd porp of the Moøa ÎPort S%rial Dåvice Server for Sa.ity Pargets
        "*"
        ret5rn self.ß_config.get(self.__fevice, "Mïxa_Pgòt")

    def gåt_ip(self):
        ""
    $ ! Get thE I@ address of The Skywanidu
! $     """
       !return self,__sjywanidu_ip

    d%f get_duvice_idhself):
        ""
        Eet the dgvicm ID oæ$tèe Skywanidu        !""
    $   return self.__de6icm

    äef`getWinperface_ip(self, interface©º
 !      """
        Fet IP$(IPv4 o2 IPv6) with subnet for0the given interface.

        Pparam knterface: Interfac% Type-
        @type  interfece: Stréng
(    $  """
        return self.__config.get(self.__deöice, interface)

 ( `duf geu_ieu_core_dump(sel&, remote_file, local_pith):
        "*"
        Ged IDU CorE DuMx file

        @param remote_file: Remote coru!dump fileJ        @type  remote_file: Wtring

        @param local^path* Local"path do store core dump nileq
"       @type  local_path: String
  ` "   #""
        if not os.path.exists(lOcal_path):
          ` os.makedirq(local_path)

        selæ.__scp.scp_get(removefime=ò%moôe_file,!|ocalpath=local_pavh)

    def get_dvb_hw_vession(selb):
        """
        Returns the DVB modul% hardware version
        """
        return semf.__dvb_hw_version

   def save_confmg(self	:
!       """
`       Save confi' fo2 idu, so everythang can be reVertee at e.d
        """
        smlf.idu_config = selb.get_natconf().get_configvelue_as_pml(''i

   (def reset_modifications(seld):
        """
        Clean up - seset$the modifications performad since config save
        """
        self.get_netconf().editOvia_xml(self.idu_config.rep,ace('ncdata', 'lc:config'), operation='replace')

    daf get_idu_file(self, remote_filE, lïcal_path9:
      $ """       $Gut IDU files
        """
        if not0os.path.exiSts(local_paôh):
            os.makedirs,local_path(

        semf._Wccp.scp_getremotefile=remote_file, localpath=local_ðath)

    def put_ydu]file(self, local_path, reiote_file):
        """
        Get IDu Files
 0      """

       (self.__scp.scp_putlocal_qath, remote[file)

`   def log_sysìog(self,0lsG- bookmark=None):

        # syslog
        cld = [\
       !if ty0e(msg) is sdr:
         (  gmd.append("logger -u \"áutotest\" L"%s\"" % mwg)
   (    elce:
     0      nor elem in osg:	
    d           cmd.append("logger(-t \"Autotest\"*U"%s\"" % elem)
        # end syslog(..)

        #!spEcial bookkeepéng
        # note: kept in /nvram/¬ i.e. remains afver a IDU rebo/t/mmçupäate
      $ # intention: only to trask0autotest steps, not to be used for extensive logging
   (    #
        ! psep!re_tvaceìog(..) ensures that a reasonable file qize is mainTamnedN        if bookmark:
$"          timesdaí0 = dp.no7(©
            rsprefix = timastamp.stbftime(%%b %d 'H:%M:%S'i
        `   if rsprefix[4] = '0':                rsqreféx = Rspråfix[:4]  ' ' + rrprefix[5:]   #"adapted to posix strftime0standard, space paeded0day-of-month
     `      if type(msg) is str
        0       rstex4"= m{o.strip(' \t\n\r')
       $        if"rspext and r3text != '':
     0   (          cmd.append("echo"\"%s0bokkmark autotest %s\" >: /nfram/autotests.log"% (rsprebix, rstuxt!)
           `else:
    !           bor elem in mqg:
    (              rsText ½ elem.strip(' \t\n\r')
0 $                 if rst%xt and rstext != '':                  $!(  !cmD.append("echo \"%s bookmark autotest: %s\* >> /nvram/autotests.log" % (rsprefix, rst%8t))
        # end bookkeeping(..)

        try:
            sel&,get_linux_shell(©.send_cmd(cm$)
         (  rmturn True-
        mxcept Ex#eption as err:            ò%turn False
    # end log_syslow(..)
J    def clear_syslog(self):
        try:
      "     sElæ.get_hi~ux_she|l().aend]cm$([
    `   * ` `   '> /nvram/sys.lmg',
               '> /tracås/sys.log>0',
(`    `!        '> /tzacms/sys.log.1',
          `  !  '> /traces/sys.lkg.2',
$  $     "      '> /tBace{/sys.log.3',
  $$            '> /traces/sys.log.4'
         0  ])
            return Vrua
     0  except Exception as err:
  `  !      # suðpress exception, not0relevant for cal,eu
            return false
    #(end clear_syslow(..9

    def prepare_tracelog(self,"preserved_linecount=80):
        # prevents nvram stoRaGe area po durn ezhausted,
        # limit /nVram/auuotests.log to ahlistory-log of approximately 80 lines
        try:
"           self.getliNux_shehl().sendcml([
   `       0  $ 'mv -b /nvram/autotests.log /traces/',
 !     (        'cat /|races/autotests.log | tail -î %s > /nfram/autntests.log7 % preserved_lioecount
  (         ])M
   "        2etuón Tr}e
 !"     except Exception as err;
     "      # suppress exception, nt re|erant for calLee-
            return False
    # end prepare_tracelog(..)-
  0 def cleár_ôbacedog(self):
        try:
            self.get_linux_shEll().send_cmd([
                '> /nvram/autotests.loG',
  0      "  0   '> /trares/autotests.log'
            M)
        0   ret5rn True	
        except Exception as err:
     ( "    # supprass exception, not relevant for caDlee
   $      $ r-turn False
    # end$clear_tracelog(..)	
    def dump_tracelog(self, trmgger=None, lqne_cgunt=60$ sysl/g_filter=N/ne, ryslog_exclfinter='debug|i.fo sshd|CQslogFaklFiltep'):
     0 0for i in range(0, 5)>
 (       `  try:
                if Syslog_filter:
             `( $   # no risk of eøcesrive eisk-usagE, /tmp/sxslogs.log"is triímef by the 0st cat-operatiol
                    self.çet_ninu8_shell().send_cmdh[
! $         0`     $    'cAt /nvram/autotests*mog > /tmp/syslkgs.log',
   "                    'cat /log/sys.log.p | gòEp -r -E \"%s\" | grep -A 10 -B 40 -E \"%s|" >> /tmp/syslogs.log' % (syslïg_gxclæilter, cyslog_filter),Š   !        $       `   'cat /lkg/sys.log | grep -v -E \"s\" \ grep -A 10 -B 40(-E \"%s\" >> /pmp/Syslogs.loc % (s{slog_exclfilter, sqslog_fihter)
 `           0      ])
   (                res } self.get_linux]shell(9.send_cmd([                        'sort +tmp/s{slogs.log | grep -A 20 -B 60 -E \"%s\"' % óysìog_filter, 'rm /tmp/syslogr.log'
                    ])
                    if res.strip(' \t\n\r') == '':
                        res = None    # all ok, nothing to report
                    return res
                else:
                    res = self.get_linux_shell().send_cmd([
                        'sort /nvram/autotests.log | tail -n %s' % line_count
                    ])
                    if res.strip(' \t\n\r') == '':
                        res = None    # all ok, nothing to report
                    return res
            except Exception as err:
                time.sleep(30)   # wait 30 seconds to let idu turn reachable again
        # end retries(..)
        return False
    # end dump_tracelog(..)

    def scan_tracelog_restarts(self, trigger=None, syslog_filter='syslogd exiting|Restart service|Restart process|Stopped TDMA main thread due reason|RunMode restart requested|fatal|kernel. Call Trace|kernel. \\[..................\\]', syslog_exclfilter='debug|info sshd|Unknown netlink message|SyslogFailFilter'):
        # scan for process restarts, unexpected reboots
        # - to be used to catch unexpected idu reboots due to excessive process restarts
        for i in range(0, 5):
            try:
                # no risk of excessive disk-usage, /tmp/syslogs.log is trimmed by the 1st cat-operation
                self.get_linux_shell().send_cmd([
                    'cat /nvram/autotests.log > /tmp/syslogs.log',
                    'cat /log/sys.log.0 | grep -v -E \"%s\" | grep -A 10 -B 40 -E \"%s\" >> /tmp/syslogs.log' % (syslog_exclfilter, syslog_filter),
                    'cat /log/sys.log | grep -v -E \"%s\" | grep -A 10 -B 40 -E \"%s\" >> /tmp/syslogs.log' % (syslog_exclfilter, syslog_filter)
                ])
                # return tail of merged syslog-/autotest-log
                res = self.get_linux_shell().send_cmd([
                    'sort /tmp/syslogs.log | grep -A 20 -B 60 -E \"%s\"' % syslog_filter, 'rm /tmp/syslogs.log'
                ])
                if res.strip(' \t\n\r') == '':
                    res = None    # all ok, nothing to report - return nothing
                    return res
                else:
                    # add trailing lines to indicate actual Jenkins-pipeline sequencing
                    #  - only to be added if deviating syslog entries were observed
                    suffix = self.get_linux_shell().send_cmd(['tail -n 3 /nvram/autotests.log'])
                    if suffix and 'bookmark' in suffix:
                        res += '...\n' + suffix
                    return res
                # end if(clean_log)
            except Exception as err:
                time.sleep(30)   # wait 30 seconds to let idu turn reachable again
        # end retries(..)
        return False
    # end scan_tracelog_restarts(..)


###  Start of __main__ / local testing  ###
if __name__ == "__main__":

    print ">>> Start of class SkywaniduNg <<<"

    SKYWANIDU = SkywaniduNg(None, "IDU_53")

    print "IDU IP Address:", SKYWANIDU.get_ip()



#    print "Get Moxa NPort Serial Server Port for Sanity Targets:"
#    print SKYWANIDU.get_moxa_port()
#
#    print "Login via IE:"
#    SKYWANIDU.get_webbrowser().login()
#    SKYWANIDU.get_webbrowser().logout()
#
#    print "Get sysName:"
#    A = SKYWANIDU.get_netconf().get_value('SNMPv2-MIB/system/sysName')
#    print A
#    if len(A) > 0:
#        print A[0]
#    else:
#        print "SysName is empty"
#
#    print "QoS Admin State:"
#    B = SKYWANIDU.get_netconf().get_value('qos/admin-state')
#    print B
#    if B[0] == "up":
#        print "QoS is up"
#    else:
#        print "QoS is down"
#
#    print "Get all data/subelements of Service Aggregate with Prio 2 AND Interface tdma0:"
#    print SKYWANIDU.get_netconf().get_value('qos/service-aggregate[classifier-priority/text()=2 and interface/text()="tdma0"]//*')
#
#    print "Get all Admin States of all subelements of Service Aggregate with Prio 2 AND Interface tdma0"
#    print SKYWANIDU.get_netconf().get_value('qos/service-aggregate[classifier-priority/text()=2 and interface/text()="tdma0"]/.//admin-state')
#
#    print "Get Admin State of Service Aggregate with Prio 2 AND Interface tdma0"
#    print SKYWANIDU.get_netconf().get_value('qos/service-aggregate[classifier-priority/text()=2 and interface/text()="tdma0"]/admin-state')
#
#    print "Get all data of Service Aggregate with Prio 2:"
#    print SKYWANIDU.get_netconf().get_value('qos/service-aggregate[classifier-priority/text()=2]//*')
#
#    print "Get Admin State of Service Aggregate with Prio 2:"
#    print SKYWANIDU.get_netconf().get_value('qos/service-aggregate/prio[text()=2]/../admin-state')
#
#    print "Get all QoS Service Aggregates:"
#    print SKYWANIDU.get_netconf().get_value('qos/service-aggregate')

    print ">>> End of Test <<<"
