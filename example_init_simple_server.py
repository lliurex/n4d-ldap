#!/usr/bin/python
import xmlrpclib


ip_server = '10.0.0.248'

c = xmlrpclib.ServerProxy("https://"+ip_server+":9779")
#c = xmlrpclib.ServerProxy("https://192.168.1.2:9779")
user = ("lliurex","lliurex")
#print c.get_methods("SlapdManager")
print c.generate_ssl_certificates(user,"SlapdManager") 
print c.load_lliurex_schema(user,"SlapdManager") 
print c.enable_tls_communication(user,"SlapdManager",'/etc/ldap/slapd.cert','/etc/ldap/slapd.key') 
#c.restore(user,"SlapdManager") 
#c.configure_client_slapd(user,"SlapdManager") 
#c.configure_master_slapd(user,"SlapdManager") 
print c.configure_simple_slapd(user,"SlapdManager") 
print c.load_acl(user,"SlapdManager")
print c.open_ports_slapd(user,"SlapdManager",ip_server) 
print c.reboot_slapd(user,"SlapdManager") 
print c.load_basic_struture(user,"SlapdManager")
print c.change_admin_passwd(user,"SlapdManager","lliurex")
print c.enable_folders(user,"SlapdManager")
#c.update_index(user,"SlapdManager") 
#c.test(user,"SlapdManager") 
#c.backup(user,"SlapdManager") 
#c.load_schema(user,"SlapdManager")
'''
print c.reset_slapd(user,'SlapdManager')
'''
