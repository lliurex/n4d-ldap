#!/usr/bin/env python

import xmlrpclib as x
import sys

def get_n4d_key():
	
	try:
	
		f=open("/etc/n4d/key")
		key=f.readline().strip("\n")
		f.close()
		
	except:
		key=None
	
	return key

n4d_key=get_n4d_key()

if n4d_key!=None:
	print("[!] You need to run this program with administration privileges. Exiting...")
	sys.exit(1)

c=x.ServerProxy("https://localhost:9779")
c.load_acl(n4d_key,"SlapdManager")


