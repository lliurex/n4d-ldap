#!/usr/bin/env python
import ldap
import xmlrpclib
import sys
import os.path
import lliurex.variables.sambasid as getsambasid

class UpdateLdap:

	def __init__(self,server,path_password):
		self.n4d = xmlrpclib.ServerProxy('https://'+ server +':9779')
		self.ldap_server = 'ldap://'+server+':389'
		self.ldap_password = self.get_password(path_password)
		self.n4d_password = self.get_password('/etc/n4d/key')
		self.sid = self.n4d.get_variable(self.n4d_password,'VariablesManager','LDAP_SID')	

	def check_centre_server(self):
		if self.sid == '254':
			return True
		else:
			return False
	def get_password(self,path_password):
		if os.path.exists(path_password):
			f=open(path_password)
			lines=f.readlines()
			f.close()
			password=lines[0].replace("\n","")
			return password
		else:
			return None

	def init_vars(self):
		self.local_sambaSID = self.n4d.get_variable(self.n4d_password,'VariablesManager','SAMBASID')
		self.ldap_basedn = self.n4d.get_variable(self.n4d_password,'VariablesManager','LDAP_BASE_DN')

	def get_conection(self):

		if self.ldap_password == None:
			return None
		connect_ldap = ldap.initialize(self.ldap_server,trace_level=0)
		connect_ldap.protocol_version=3
		try:
			connect_ldap.bind_s("cn=admin," + self.ldap_basedn ,self.ldap_password)
		except Exception, e:
			pass
		return connect_ldap

	def update(self):
		connect_ldap = self.get_conection()
		if connect_ldap == None:
			return None
		items = connect_ldap.search_s(self.ldap_basedn,ldap.SCOPE_SUBTREE,'objectClass=sambaDomain')
		list_update_dn = []
		#get dn hasn't equal sambasid
		for x in items:
			try:
				if x[1]['sambaSID'] != self.local_sambaSID:
					list_update_dn.append(x[0])
			except:
				pass
		#update dn
		for dn in list_update_dn:
			update_sambasid = [(ldap.MOD_REPLACE,'sambaSID',self.local_sambaSID)]
			try:
				connect_ldap.modify_s(dn,update_sambasid)
			except:
				pass
		return True

	def run(self):
		if self.check_centre_server():
			self.init_vars()
			self.update()


if __name__ == '__main__':
	update_ldap = UpdateLdap('localhost','/etc/lliurex-secrets/passgen/ldap.secret')
	update_ldap.run()
