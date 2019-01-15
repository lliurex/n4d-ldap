#!/usr/bin/python
import xmlrpclib as x
import shutil
import time
f = open('/etc/n4d/key','r')
key = f.readline().strip()
c = x.ServerProxy('https://localhost:9779')
done = False
while not done:
	try:
		x = c.get_methods("SlapdManager")
		if "load_acl" in x : 
			done = True
			if c.get_variable("","VariablesManager","SRV_IP") != None:
				c.load_acl(key,"SlapdManager")
			break
	except:
		pass
	time.sleep(2)

