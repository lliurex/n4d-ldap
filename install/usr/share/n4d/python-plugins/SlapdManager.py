import ldap
import ldap.sasl
import ldap.modlist
import os
import os.path
import ast
from jinja2 import Environment
from jinja2.loaders import FileSystemLoader
from jinja2 import Template
import base64
import random
import string
import hashlib
import subprocess
import tempfile
import shutil

__DEBUGGING__=False
__DEBUG_PRINT__=False

def try_connect(f):
	def wrap(*args,**kw):
		if not args[0].test_ldapi_connection():
			if not args[0].connection_ldapi():
				return {"status":False,"msg":"Connection with ldapi is not created"}
		return f(*args)
	return wrap
#def __try_connect__

if __DEBUGGING__:
	__TEMPLATES_SLAPD_PATH__='/home/lliurex/git/n4d-ldap/install/usr/share/n4d/templates/slapd'
	def n4d_mv(o,d):
		shutil.copy2(o,d)
	class FakeObject:
		def __init__(self):
			self.o = {'LDAP_BASE_DN':'dc=ma5,dc=lliurex,dc=net'}
		def p(self,*args):
			if __DEBUG_PRINT__:
				import inspect
				l = ['*****']
				l.append(inspect.stack()[1][3])
				for x in args:
					l.append('{}'.format(x))
				l.append('*****')
				print(' '.join(l))
		def init_variable(self,name,value=''):
			self.p(name,value)
			self.o['name']=value
		def get_variable_list(self,lista):
			self.p(lista)
			r={}
			for x in lista:
				r[x]=self.get_variable(x)
			self.p('RESULT',r)
			return r
		def get_variable(self,name):
			self.p(name)
			if name not in self.o.keys():
				self.p('UNKNOWN',name)
				import sys
				sys.exit(1)
			else:
				self.p('RESULT',self.o[name])
				return self.o[name]
		def set_variable(self,name,value):
			self.p('SET VARIABLE',name,value)
			if name in self.o:
				self.o[name]=value

	objects={'VariablesManager': FakeObject()}

class SlapdManager:
	
	predepends = ['VariablesManager']
	
	def __init__(self):
		# Vars
		self.LDAP_SECRET1 = '/etc/lliurex-cap-secrets/ldap-master/ldap'
		self.LDAP_SECRET2 = '/etc/lliurex-secrets/passgen/ldap.secret'
		self.log_path = '/var/log/n4d/sldap'
		self.enable_acl_path = '/var/lib/n4d-ldap/enable_acl'
		if not __DEBUGGING__:
			self.tpl_env = Environment(loader=FileSystemLoader('/usr/share/n4d/templates/slapd'))
		else:
			try:
				__TEMPLATES_SLAPD_PATH__
				self.tpl_env = Environment(loader=FileSystemLoader(__TEMPLATES_SLAPD_PATH__))
			except:
				print('NEED TO SET __TEMPLATES_SLAPD_PATH__ Example: /home/lliurex/git/n4d-ldap/install/usr/share/n4d/templates/slapd')
				import sys
				sys.exit(1)
	#def __init__
	
	def apt(self):
		'''
		options={}
		options["groups"] = ["adm","admins"]
		options["visibility"] = True
		esto es un comentario que funciona de la siguiente forma
			asi
		'''
		pass
	#def apt
	
	def startup(self,options):
		if objects['VariablesManager'].get_variable('LDAP_BASE_DN') is None:
			objects['VariablesManager'].init_variable('LDAP_BASE_DN')
		self.connection_ldapi()
		self.connection_ldap()
	#def startup
	
	def test(self):
		pass
	#def test
	
	def backup(self, folder_path="/backup/"):
		try:
			if not folder_path.endswith("/"):
				folder_path+="/"
			file_path = folder_path + get_backup_name("Slapd")
			os.system("llx-slapd-backup dump " + file_path)
			objects["Golem"].ldap.restore_connection=True
			objects["Golem"].ldap.connect()
			return [True,file_path]
			
		except Exception as e:
			return [False,str(e)]
		
	#def backup
	
	def restore(self,file_path=None):
		if file_path==None:
			for f in sorted(os.listdir("/backup"),reverse=True):
				if "Slapd" in f:
					file_path="/backup/"+f
					break

		try:

			if os.path.exists(file_path):
				
				os.system("llx-slapd-backup restore " + file_path)
						
				return [True,""]
				
		except Exception as e:
				
			return [False,str(e)]
	#def restore
	
	def reset_slapd(self):
		proc = subprocess.Popen(['/usr/sbin/reset-slapd'],stdout=subprocess.PIPE,stdin=subprocess.PIPE).communicate()
		return {"status":True,"msg":"Server is reset"}
	#def reset_slapd

	@try_connect
	def load_acl(self):
		"""
		To be supplied
		"""
		
		# Get files from enable acl path ordered by number. If file name not start by number,
		# it's putting in the end ordered by letter.
		list_files_acl = os.listdir(self.enable_acl_path)
		list_files_acl.sort(lambda x,y:self.__becmp__(self.__beint__(x),self.__beint__(y)))
		
		# Prepare environment
		environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN'])
		list_acl = []
		
		# Number for ACL
		i = 0
		for x in list_files_acl:
			aux_file = open(os.path.join(self.enable_acl_path,x))
			lines = aux_file.readlines()
			aux_acl = ""
			for y in lines:
				aux_acl += y.strip() + " "
			# Render acl to replace vars
			acl_template = Template(aux_acl)
			aux_acl = acl_template.render(environment_vars).encode('utf-8')
			aux_acl = "{"+str(i)+"}" + aux_acl
			i+=1
			list_acl.append(aux_acl)
		
		remove_acl = [(ldap.MOD_DELETE,'olcAccess',None)]
		modify_list = [(ldap.MOD_ADD,'olcAccess',list_acl)]

		try:
			self.connect_ldapi.modify_s('olcDatabase={1}mdb,cn=config',self.str_to_bytes(remove_acl))
		except:		
			pass
		try:
			self.connect_ldapi.modify_s('olcDatabase={1}mdb,cn=config',self.str_to_bytes(modify_list))
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"Acl updated"}
	#def load_acl
	
	@try_connect	
	def load_schema(self,cn,schema,update=False):
		
		all_schemas = self.connect_ldapi.search_s('cn=schema,cn=config',ldap.SCOPE_SUBTREE)
		old_config = None
		for i in all_schemas:
			if cn[3:] in i[0]:
				old_cn = i[0]
				old_config = i[1]
				break
		if not old_config == None:
			if not update:
				return {"status":False,"msg":"Schema " + str(cn) + " already exist. You can update with update option on True"}
			old_config['cn'] = schema['cn']
			old_config['objectClass'] = schema['objectClass']
			changes = ldap.modlist.modifyModlist(old_config,schema)
			try:
				self.connect_ldapi.modify_s(old_cn,self.str_to_bytes(changes))
				return {"status":True,"msg":"Schema " + str(cn) +"is updated"}
			except Exception as e:
				return {"status":False,"msg":str(e)}
		else:
			changes = ldap.modlist.addModlist(schema)
			try:
				self.connect_ldapi.add_s(cn,changes)
				return {"status":True,"msg":"Loaded schema" + str(cn)}
			except Exception as e:
				return {"status":False,"msg":str(e)}
	#def load_schema
	
	@try_connect	
	def update_index(self,index,add_index=True):
	
		searching_backend = self.connect_ldapi.search_s('cn=config',ldap.SCOPE_SUBTREE,filterstr='(objectClass=olcBackendConfig)',attrlist=['olcBackend'])
		if len(searching_backend) > 0 :
			backend = searching_backend[0][1]['olcBackend'][0]
		else:
			return {"status":False,"msg":"not found backend for OpenLdap"}

		
		searching_database = self.connect_ldapi.search_s('cn=config',ldap.SCOPE_SUBTREE,filterstr='(olcDatabase~='+backend+')',attrlist=['olcDbIndex'])
		if len(searching_database) > 0 :
			cn,aux_index = searching_database[0]
		else:
			return {"status":False,"msg":"not found database config on OpenLdap"}

		if aux_index.has_key('olcDbIndex'):
			old_Index = aux_index['olcDbIndex']
		else:
			old_Index = []

		list_index = old_Index[:]
		if type(index) == type([]):
			for x in index:
				if add_index:
					list_index.append(x)
				else:
					if x in list_index:
						list_index.remove(x)
		elif type(index) == type(''):
			if add_index:
				list_index.append(index)
			else:
				if index in list_index:
					list_index.remove(index)
		list_index = list(set(list_index))
		remove_acl = [(ldap.MOD_DELETE,'olcDbIndex',[""])]
		modify_list = [(ldap.MOD_REPLACE,'olcDbIndex',list_index)]
		try:
			self.connect_ldapi.modify_s(cn,self.str_to_bytes(remove_acl))
		except Exception as e:		
			pass
		try:
			self.connect_ldapi.modify_s(cn,self.str_to_bytes(modify_list))
		except Exception as e:
			self.connect_ldapi.modify_s(cn,self.str_to_bytes([(ldap.MOD_ADD,'olcDbIndex',old_Index)]))
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"Index added"}
	#def load_index
	
	def str_to_bytes(self,thing,skip=1):
		if isinstance(thing,list):
			thing_encoded = list()
			for other in thing:
				thing_encoded.append(self.str_to_bytes(other))
			return thing_encoded
		elif isinstance(thing,dict):
			thing_encoded = dict()
			for k,v in thing.items():
				thing_encoded[k]=self.str_to_bytes(v)
			return thing_encoded
		elif isinstance(thing,tuple):
			tmp_encoded=tuple()
			for t in thing:
				if skip > 0 and isinstance(t,str):
					skip -= 1
					tmp_encoded += (t,)
				else:
					tmp_encoded += (self.str_to_bytes(t),)
			return tmp_encoded
		elif isinstance(thing,str):
			return thing.encode('utf-8')
		else:
			return thing
	
	def load_lliurex_schema(self):
		#Load template
		template = self.tpl_env.get_template("configure/lliurex_schema")
		
		#render template with config and turn string into dictionary for get modify ldif
		string_template = template.render()
		aux_dic = ast.literal_eval(string_template)
		# Update changes in ldap
		for x in aux_dic.keys():
			result = self.load_schema(x,self.str_to_bytes(aux_dic[x]),True)
			if not result['status']:
				return result
		return {"status":True,"msg":"Loaded Lliurex schema"}	
		
	#def load_lliurex_schema

	def load_basic_struture(self):
		"""
			Load on ldap database root dn and other basics things
		"""
		if not self.test_ldap_connection():
			if not self.connection_ldap():
				return {"status":False,"msg":"Connection with ldap is not created"}
		
		#Prepare environment
		template = self.tpl_env.get_template('struct/base')
		environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN'])
		
		#render template with config and turn string into dictionary for get modify ldif
		string_template = template.render(environment_vars)
		aux_dic = ast.literal_eval(string_template)
		
		#Load basic strucutre
		result = self.insert_dictionary(aux_dic)
		if result['status']:
			return {"status":True,"msg":"Root structure created"} 
		else:
			return {"status":True,"msg":"Root structure already exists"}
	#def load_basic_structure
	
	
	def insert_dictionary(self,dictionary,i_existing=False,f_update=False):
		"""
		"""
		if not self.test_ldap_connection():
			if not self.connection_ldap():
				return {"status":False,"msg":"Connection with ldap is not created"}
	
		if not type(dictionary) == type({}):
			return {"status":False,"msg":"argument isn't python dictionary "}
		dictionary_keys = dictionary.keys()
		dictionary_keys = sorted(dictionary_keys,key=lambda x: len(x.split(',')))
		aux_msg = ""
		for x in dictionary_keys:
			try:
				add_entry = ldap.modlist.addModlist(dictionary[x])
				self.connect_ldap.add_s(x,add_entry)
			except ldap.ALREADY_EXISTS as e:
				if i_existing:
					aux_msg += "\nEntry " + str(x) + " has been omited because already exists"
				else:					
					return {"status":False ,"msg":"Entry " + str(x) + " already exists"}
			except Exception as e:
				return {"status":False ,"msg":"Entry " + str(x) + " isn't possible create because "+ str(e)}
		return {"status":True,"msg":"All entry added" + aux_msg}
	#def insert_dictionary
	
	
	def delete_dn(self, dn):
		if not self.test_ldap_connection():
			if not self.connection_ldap():
				return {"status":False,"msg":"Connection with ldap is not created"}
		try:
			self.connection_ldap.delete_s(dn)
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"Deleted dn"}
	#def delete_dn
	
	def recursive_delete(self,dn):
		try:
			result = self.connect_ldap.search_s(dn,ldap.SCOPE_ONELEVEL)
		except ldap.NO_SUCH_OBJECT as e:
			return
		if len(result) > 0 :
			for x in result:
				self.recursive_delete(x[0])
		self.connect_ldap.delete_s(dn)
		return {"status":True, "msg":"Deleted " + str(dn)}
	#def recursive_delete

	@try_connect	
	def enable_tls_communication(self,cert_path,key_path):
		""" 
			Enable ssl for connection
		"""
		
		# Remove old password and add new password . 1 = delete, 0 = add
		remove_tls = [(ldap.MOD_DELETE,'olcTLSCertificateFile',None),(ldap.MOD_DELETE,'olcTLSCertificateKeyFile',None),(ldap.MOD_DELETE,'olcTLSVerifyClient',None)]
		modify_list = [(ldap.MOD_ADD,'olcTLSCertificateFile',cert_path),(ldap.MOD_ADD,'olcTLSCertificateKeyFile',key_path),(ldap.MOD_ADD,'olcTLSVerifyClient','never')]

		try:
			self.connect_ldapi.modify_s('cn=config',self.str_to_bytes(remove_tls))
		except:		
			pass
		try:
			self.connect_ldapi.modify_s('cn=config',self.str_to_bytes(modify_list))
		except Exception as e:
			return {"status":False,"msg":str(e)}
		
		self.connection_ldap()
		return {"status":True,"msg":"SSL is Enabled"}
	#def enable_tls_communication

	@try_connect	
	def change_admin_passwd(self,password):
		"""
			Update ldap admin password and write this inside LDAP_SECRET2 
		"""
		
		ssha_password = self.generate_ssha_password(password)
		# Remove old password and add new password . 1 = delete, 0 = add
		modify_list = [(ldap.MOD_DELETE, 'olcRootPW', None), (ldap.MOD_ADD, 'olcRootPW', ssha_password)]
		try:
			self.connect_ldapi.modify_s('olcDatabase={1}mdb,cn=config',self.str_to_bytes(modify_list))
		except Exception as e:
			return {"status":False,"msg":e[0]["desc"]}
		
		#reconnect
		try:
			environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN'])
			self.connect_ldap.bind_s("cn=admin,"+environment_vars['LDAP_BASE_DN'],password)
		except:
			self.connect_ldap = None
		
		#Only write password file success case
		password_file = open(self.LDAP_SECRET2,'w')
		password_file.write(password+"\n")
		password_file.close()
		os.chmod(self.LDAP_SECRET2,0o0600)
		return {"status":True,"msg":"Ldap admin password updated"}
	#def change_admin_passwd
	def remove_wrong_operations(self,changelist):
		wrongkeys = [ 'olcDatabase', 'objectClass', 'olcDbDirectory' ]
		return [ (op,key,value) for op,key,value in changelist if key not in wrongkeys ]
			
	@try_connect	
	def configure_simple_slapd(self,admin_password=None):
		"""
			This function configure openldap as simple ldap. If admin_password isn't defined
			it's generated by generate_random_ssha_password, with 10 characters.
		"""
		
		# get config template and vars
		template = self.tpl_env.get_template("configure/basic")
		environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN'])
		
		# generate ssha password 
		if admin_password is None:
			ssha_password,admin_password = self.generate_random_ssha_password()
		else:
			ssha_password = self.generate_ssha_password(admin_password)
		environment_vars['PASSWORD_CRYPTED'] = ssha_password.strip()
		
		#render template with config and turn string into dictionary for get modify ldif
		string_template = template.render(environment_vars)
		aux_dic = ast.literal_eval(string_template)
		
		# Update changes in ldap 
		for x in aux_dic.keys():
			old_config = self.connect_ldapi.search_s(x,ldap.SCOPE_SUBTREE)
			if len(old_config) > 0:
				old_config = old_config[0][1]
			changes = ldap.modlist.modifyModlist(old_config,aux_dic[x])
			changes = self.remove_wrong_operations(changes)
			try:
				self.connect_ldapi.modify_s(x,self.str_to_bytes(changes))
			except Exception as e:
				return {"status":False,"msg":e[0]["desc"]}
		
		modify_list = [(ldap.MOD_ADD, 'olcSizeLimit', 'unlimited')]
		try:
			self.connect_ldapi.modify_s('cn=config',self.str_to_bytes(modify_list))
		except Exception as e:
			return {"status":False,"msg":e[0]["desc"]}

		#Delete file password because this is a simple server
		if os.path.exists(self.LDAP_SECRET1):
			os.remove(self.LDAP_SECRET1)
		
		#reconnect
		try:
			self.connect_ldap.bind_s("cn=admin,"+environment_vars['LDAP_BASE_DN'],admin_password)
		except:
			self.connect_ldap = None
		
		# If update config success then update file with new password
		password_file = open(self.LDAP_SECRET2,'w')
		password_file.write(admin_password+"\n")
		password_file.close()
		os.chmod(self.LDAP_SECRET2,0o0600)
		
		
		#set bigger db size
		
		modify_list = [(ldap.MOD_DELETE, 'olcDbMaxSize', None)]
		try:
			self.connect_ldapi.modify_s('olcDatabase={1}mdb,cn=config',self.str_to_bytes(modify_list))
		except Exception as e:
			# ignore this exception.
			pass
			
		modify_list = [(ldap.MOD_ADD, 'olcDbMaxSize', "209715200")]
		try:
			self.connect_ldapi.modify_s('olcDatabase={1}mdb,cn=config',self.str_to_bytes(modify_list))
		except Exception as e:
			return {"status":False,"msg":e[0]["desc"]}

		
		return {"status":True,"msg":"OpenLdap is configured as simple ldap. Admin password is inside " + self.LDAP_SECRET2}

	#def configure_simple_slapd
	
	def configure_master_slapd(self):
		pass
	#def configure_master_slapd
	
	def configure_client_slapd(self):
		pass
	#def configure_client_slapd
	
	def open_ports_slapd(self,server_ip):
		
		CLIENT_LDAP_URI = 'ldaps://'+ str(server_ip)
		CLIENT_LDAP_URI_NOSSL = 'ldap://'+ str(server_ip)
		
		open_ports = 'ldap://:389/ ldapi:///'
		connection_ok = True
		if not self.test_ldapi_connection():
			if self.connection_ldapi:
				connection_ok = False
		if connection_ok:
			try:
				ok_token = True
				result = self.connect_ldapi.search_s('cn=config',ldap.SCOPE_BASE,attrlist=['olcTLSCertificateKeyFile','olcTLSCertificateFile'])[0][1]
				if result.has_key('olcTLSCertificateKeyFile'):
					if not os.path.exists(result['olcTLSCertificateKeyFile'][0]):
						ok_token = False
				if ok_token and result.has_key('olcTLSCertificateFile'):
					if not os.path.exists(result['olcTLSCertificateFile'][0]):
						ok_token = False
				if ok_token:
					open_ports += " ldaps:///"
			except:
				pass
		slapd_file = open('/etc/default/slapd','r')
		list_lines = slapd_file.readlines()
		slapd_file.close()
		
		fd, tmpfilepath = tempfile.mkstemp()
		new_slapd_file = open(tmpfilepath,'w')
		for line in list_lines:
			if line.startswith('SLAPD_SERVICES='):
				new_slapd_file.write('SLAPD_SERVICES="'+open_ports+'"\n')
			else:
				new_slapd_file.write(line)
		new_slapd_file.close()
		os.close(fd)
		
		n4d_mv(tmpfilepath,'/etc/default/slapd')
		if 'ldaps:' in open_ports:
			environment_vars = objects["VariablesManager"].init_variable('CLIENT_LDAP_URI',{'uri':CLIENT_LDAP_URI})
		environment_vars = objects["VariablesManager"].init_variable('CLIENT_LDAP_URI_NOSSL',{'uri':CLIENT_LDAP_URI_NOSSL})
		return {"status":True,"msg":"Open ports " + open_ports}
	#def open_ports_slapd
	
	def reboot_slapd(self):
		
		proc = subprocess.Popen(['systemctl','restart',"slapd"],stdout=subprocess.PIPE,stdin=subprocess.PIPE).communicate()
		
		return {"status":True,"msg":"Server is reboot"}
	#def reboot_slapd
	
	def generate_ssl_certificates(self):
		
		proc = subprocess.Popen(['/usr/sbin/n4d-ldap-generator-ssl'],stdout=subprocess.PIPE,stdin=subprocess.PIPE).communicate()
		
		return {"status":True,"msg":"Certificates ssl has been generated"}
	#def generate_ssl_certificates
	
	def enable_folders(self):
		shutil.copy('/usr/share/n4d/templates/folder/share','/var/lib/lliurex-folders/local/share')
		shutil.copy('/usr/share/n4d/templates/folder/teachers_share','/var/lib/lliurex-folders/local/teachers_share')
		shutil.copy('/usr/share/n4d/templates/folder/students','/var/lib/lliurex-folders/local/students')
		shutil.copy('/usr/share/n4d/templates/folder/teachers','/var/lib/lliurex-folders/local/teachers')
		shutil.copy('/usr/share/n4d/templates/folder/admins','/var/lib/lliurex-folders/local/admins')
		shutil.copy('/usr/share/n4d/templates/folder/netadmin','/var/lib/lliurex-folders/local/netadmin')
		return {"status":True,"msg":"Folders are enabled."}
	#def enable_folders
	
	def disable_folders(self):
		os.remove('/var/lib/lliurex-folders/local/share')
		os.remove('/var/lib/lliurex-folders/local/teachers_share')
		os.remove('/var/lib/lliurex-folders/local/students')
		os.remove('/var/lib/lliurex-folders/local/teachers')
		return {"status":True,"msg":"Folders are disabled."}
	#def disable_folders
	
	
	def set_replicate_interface(self, interface ):
		return objects['NetworkManager'].set_replicate_interface(interface)
	#def set_replicate_interface

	@try_connect	
	def set_serverid(self, id_server,ip=None):
		list_ip = id_server
		if ip != None:
			list_ip += " ldap://" + ip + "/"
		remove_olcserver = [(ldap.MOD_DELETE,'olcServerID',None)]
		modify_olcserver = [(ldap.MOD_ADD,'olcServerID',list_ip)]
		objects['VariablesManager'].init_variable('LDAP_SID',{"SID":id_server})
		try:
			self.connect_ldapi.modify_s('cn=config',self.str_to_bytes(remove_olcserver))
		except:		
			pass
		try:
			self.connect_ldapi.modify_s('cn=config',self.str_to_bytes(modify_olcserver))
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status": True, "msg":"This server now has ServerID " + str(id_server) + " on ldap"}
		
	#def set_serverid
	
	@try_connect	
	def get_serverid(self):
		try:
			result = self.connect_ldapi.search_s("cn=config",ldap.SCOPE_BASE)[0][1]['olcServerID']
		except Exception as e:
			return {"status":False,"msg":"ServerID isn't defined"}
		return {"status":True,"msg":result}
		
	#def get_serverid
	
	@try_connect	
	def append_serverid(self, id_server, ip):
		result = self.get_serverid()
		if result['status']:
			#EXIST OTHER ID SERVER
			for i in result['msg']:
				if i.startswith(id_server+" ") or i == id_server:
					return{"status":False,"msg":"This id has been registered"}
				
			if len(result['msg']) == 1:
				aux_ip = get_ip(objects['VariablesManager'].get_variable('INTERFACE_REPLICATION'))
				if aux_ip == None :
					return {"status":False,"msg":"Replication interface has a problem with ip. Check it"}
				aux_sid = result['msg'][0].split(' ')[0]
				self.set_serverid(aux_sid,str(aux_ip))

		list_ip = str(id_server) + " ldap://"+str(ip) + "/"
		modify_olcserver = [(ldap.MOD_ADD,'olcServerID',list_ip)]

		try:
			self.connect_ldapi.modify_s('cn=config',self.str_to_bytes(modify_olcserver))
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":ip + " has been appended"}
	#def append_serverid

	@try_connect
	def delete_serverid(self, ip):
		result = self.get_serverid()
		if result['status']:
			for i in result['msg']:
				if i.rstrip('/').endswith(ip):
					result['msg'].remove(i)
			modify_olcserver = [(ldap.MOD_REPLACE,'olcServerID',result['msg'])]
		else:
			return {"status":False,"msg":"server hasn't server ID key"}
		try:
			self.connect_ldapi.modify_s('cn=config',self.str_to_bytes(modify_olcserver))
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"Server with ip " + ip + " has been delete"}
	#def delete_server
	
	@try_connect
	def set_serverid_batch(self, list_serverid):
		result = self.get_serverid()
		modify_olcserver = []
		if result['status']:
			modify_olcserver.append((ldap.MOD_REPLACE,'olcServerID',list_serverid))
		else:
			modify_olcserver.append((ldap.MOD_ADD,'olcServerID',list_serverid))
		try:
			self.connect_ldapi.modify_s('cn=config',self.str_to_bytes(modify_olcserver))
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"OlcServerId is updated"}
	


	@try_connect
	def enable_module(self, name):
		try:
			self.connect_ldapi.modify_s('cn=module{0},cn=config',self.str_to_bytes([(ldap.MOD_ADD,'olcModuleLoad',name)]))
		except Exception as e:
			return {'status':False,'msg':str(e)}
		return {'status':True,'msg': 'module' + str(name) + ' has been enabled' }
		
	#def enable_module

	def enable_replication_module(self):
		result = self.enable_module('syncprov.la')
		return result
	#def enable_replication_module


	@try_connect
	def get_password_config(self):
		try:
			password = self.connect_ldapi.search_s('olcDatabase={0}config,cn=config',ldap.SCOPE_BASE)[0][1]['olcRootPW'][0]
		except Exception as e:
			return {"status":False,"msg":"Password is not defined"}
		return {"status":True,"msg":password}
	#def get_password_config
	
	@try_connect
	def set_password_config(self, password):
		try:
			if len(self.connect_ldapi.search_s('olcDatabase={0}config,cn=config',ldap.SCOPE_BASE,attrlist=['olcRootPW'])[0][1]) == 0:
				changes = [(ldap.MOD_ADD,'olcRootPW',password)]
			else:
				changes = [(ldap.MOD_REPLACE,'olcRootPW',password)]
			self.connect_ldapi.modify_s('olcDatabase={0}config,cn=config',self.str_to_bytes(changes))
		except Exception as e:
			return {"status":False,"msg" : str(e)}
		return {"status": True, "msg" : "Password is set"}
	#def set_password_config
	
	@try_connect
	def delete_password_config(self):
		try:
			changes = [(ldap.MOD_DELETE,'olcRootPW')]
			password = self.connect_ldapi.modify_s('olcDatabase={0}config,cn=config',self.str_to_bytes(changes))
		except Exception as e:
			return {"status":False,"msg":"Password is not defined"}
		return {"status":True,"msg":"Removed password from database config"}
	#def delete_password_config
	

	@try_connect
	def enable_overlay_config(self):
		x = {'objectClass': ['olcOverlayConfig', 'olcSyncProvConfig'], 'olcOverlay': 'syncprov'}
		dn = 'olcDatabase={0}config,cn=config'
		try:
			result = self.connect_ldapi.search_s(dn,ldap.SCOPE_ONELEVEL)
			for x in result:
				if 'syncprov' in x[0]:
					return {"status":True,"msg":"Overlay has been enabled on the past"}
			
		except ldap.NO_SUCH_OBJECT as e:
			pass
		except Exception as e:
			return {"status":False,"msg":str(e)}

		add_entry = ldap.modlist.addModlist(x)
		self.connect_ldapi.add_s('olcOverlay=syncprov,' + dn,add_entry)

		return {"status":True,"msg":"Overlay is enabled"}
	#def enable_overlay_config
	
	@try_connect
	def enable_overlay_data(self):
		x = {'objectClass': ['olcOverlayConfig', 'olcSyncProvConfig'], 'olcOverlay': 'syncprov'}
		dn = 'olcDatabase={1}mdb,cn=config'
		try:
			result = self.connect_ldapi.search_s(dn,ldap.SCOPE_ONELEVEL)
			for x in result:
				if 'syncprov' in x[0]:
					return {"status":True,"msg":"Overlay has been enabled on the past"}	
		except ldap.NO_SUCH_OBJECT as e:
			pass
		except Exception as e:
			return {"status":False,"msg":str(e)}

		add_entry = ldap.modlist.addModlist(x)
		self.connect_ldapi.add_s('olcOverlay=syncprov,' + dn,add_entry)
		return {"status":True,"msg":"Overlay is enabled"}
	#def enable_overlay_data
	
	@try_connect
	def add_rid_config(self, rid, ip, password):
		dn = 'olcDatabase={0}config,cn=config'
		template = 'rid=%(rid)03d provider=ldap://%(ip)s/ binddn="cn=config" bindmethod=simple credentials=%(password)s searchbase="cn=config" type=refreshAndPersist retry="5 5 300 5" timeout=1 schemachecking=off tls_reqcert=never'
		try:
			result = self.connect_ldapi.search_s('olcDatabase={0}config,cn=config',ldap.SCOPE_BASE)[0][1]
			changes = []
			if (not result.has_key('olcSyncrepl')):
				server_id = objects['VariablesManager'].get_variable('LDAP_SID')
				aux_ip = get_ip(objects['VariablesManager'].get_variable('INTERFACE_REPLICATION'))
				if aux_ip == None:
					return {"status":False,"msg":"Replication interface has a problem with ip. Check it"}
				aux_result = self.get_password_config()
				if not aux_result['status']:
					return {"status":False,"msg":"Error on password config"}
				changes.append((ldap.MOD_ADD,'olcSyncrepl',template%{'rid':int(server_id),'ip':aux_ip,'password':str(aux_result['msg'])}))
				changes.append((ldap.MOD_ADD,'olcMirrorMode','TRUE'))
				
			changes.insert(0,(ldap.MOD_ADD,'olcSyncrepl',template%{'rid':int(rid),'ip':str(ip),'password':str(password)}))
			
			try:
				self.connect_ldapi.modify_s(dn,self.str_to_bytes(changes))
			except Exception as e:
				return {"status":False,"msg":str(e)}

		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"Server is join"}
	#def add_rid_config

	@try_connect
	def remove_rid_config(self, ip):
		pass
	#def remove_rid_config
	
	@try_connect
	def set_rid_config(self, list_rid):
		dn = 'olcDatabase={0}config,cn=config'
		
		delete_chages = [(ldap.MOD_DELETE,'olcSyncrepl')]
		new_changes = [(ldap.MOD_ADD,'olcSyncrepl',list_rid)]
		try:
			self.connect_ldapi.modify_s(dn,self.str_to_bytes(delete_chages))
		except Exception as e:
			pass
		try:
			self.connect_ldapi.modify_s(dn,self.str_to_bytes(new_changes))
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"set news rids"}
	#def set_rid_config
	
	@try_connect
	def get_rid_config(self):
		try:
			result = self.connect_ldapi.search_s('olcDatabase={0}config,cn=config',ldap.SCOPE_BASE)[0][1]['olcSyncrepl']
		except Exception as e:
			return {"status":False,"msg":"ServerID isn't defined"}
		return {"status":True,"msg":result}
	#def get_rid_config
	
	
	def backup_config(self, path):
		os.system("slapcat -n 0 >> " + str(path))
		prevmask = os.umask(0)
		os.chmod(path,0o0600)
		os.umask(prevmask)
		return {"status":True,"msg":"Backup created on " + str(path)}
	#def backup_config
	
	def restore_backup_config(self, path):
		os.system("systemctl stop slapd")
		os.system("rm -fr /etc/ldap/slapd.d/*")
		os.system("slapadd -n 0 -l "+path+" -F /etc/ldap/slapd.d/")
		os.system("chown -R openldap:openldap /etc/ldap/slapd.d/")
		os.system("systemctl start slapd")
		return {"status":True,"msg":"Config backup restored"}
	
	
	
	@try_connect
	def add_rid_data(self, rid, ip, password, rootdn, basedn):
		dn = 'olcDatabase={1}mdb,cn=config'
		'''
			rid
			ip
			rootdn
			password
			basedn
		'''
		template = 'rid=%(rid)03d provider=ldap://%(ip)s/ binddn="%(rootdn)s" bindmethod=simple credentials=%(password)s searchbase="%(basedn)s" type=refreshOnly interval=00:00:00:10 retry="5 5 300 5" timeout=1 schemachecking=off tls_reqcert=never'
		try:
			result = self.connect_ldapi.search_s(dn,ldap.SCOPE_BASE)[0][1]
			changes = []
			
			if (not result.has_key('olcSyncrepl')):
				aux_base_dn = objects['VariablesManager'].get_variable('LDAP_BASE_DN')
				if result.has_key('olcRootDN') and len(result['olcRootDN']) > 0 :
					aux_rootdn = result['olcRootDN'][0]
				else:
					return {"status":False,"msg":"Error on LDAP database. There isn't rootdn"}
				
				server_id = objects['VariablesManager'].get_variable('LDAP_SID')
				aux_ip = get_ip(objects['VariablesManager'].get_variable('INTERFACE_REPLICATION'))
				if aux_ip == None:
					return {"status":False,"msg":"Replication interface has a problem with ip. Check it"}
				aux_file = open(self.LDAP_SECRET2,'r')
				aux_password = aux_file.readline().strip()
				aux_file.close()
				changes.append((ldap.MOD_ADD,'olcLimits','dn.exact="%s" time.soft=unlimited time.hard=unlimited size.soft=unlimited size.hard=unlimited'%str(aux_rootdn)))
				changes.append((ldap.MOD_ADD,'olcSyncrepl',template%{'rid':int(server_id),'ip':aux_ip,'password':str(aux_password),'rootdn':str(aux_rootdn),'basedn':str(aux_base_dn)}))
				changes.append((ldap.MOD_ADD,'olcDbIndex','entryUUID  eq'))
				changes.append((ldap.MOD_ADD,'olcDbIndex','entryCSN  eq'))
			else:
				changes.append((ldap.MOD_ADD,'olcSyncrepl',template%{'rid':int(rid),'ip':str(ip),'password':str(password),'rootdn':str(rootdn),'basedn':str(basedn)}))
				if not result.has_key('olcMirrorMode'):
					changes.append((ldap.MOD_ADD,'olcMirrorMode','TRUE'))

			try:
					self.connect_ldapi.modify_s(dn,self.str_to_bytes(changes))
			except Exception as e:
					return {"status":False,"msg":str(e)}

		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"Server is join"}
	#def add_rid_data
	
	@try_connect
	def remove_rid_data(self, ip):
		pass
	#def remove_rid_data
	
	
	def block_replication(self):
		template = 'iptables -A INPUT -p tcp --dport %(port)s -s %(ip)s -j ACCEPT'
		negate = 'iptables -A INPUT -p tcp --dport %(port)s -j DROP'
		ip = get_ip(objects['VariablesManager'].get_variable('INTERFACE_REPLICATION'))
		iptables_rules = [template%{'ip':'127.0.0.1','port':'389'},template%{'ip':'127.0.0.1','port':'636'},template%{'port':'389','ip':str(ip)},template%{'port':'636','ip':str(ip)},negate%{'port':'389'},negate%{'port':'636'}]
		for x in iptables_rules:
			os.system(x)
		return {"status":True,"msg":"Replication is block"}
	#def block_replication
	
	def unblock_replication(self):
		p=subprocess.Popen(["iptables-save"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		output=p.communicate()[0].split("\n")
		ret=[]
		for item in output:
			if "--dport 389" in item or "--dport 636" in item:
				ret.append("iptables " + item.replace("-A","-D"))

		for item in ret:
			os.system(item)
		return {"status":True,"msg":"replication blockec is removed"}
	#def unblock_replication
	
	@try_connect
	def get_csn_config(self):
		try:
			csn = self.connect_ldapi.search_s('cn=config',ldap.SCOPE_BASE,attrlist=['contextCSN'])
		except Exception as e:
			return {"status":False,"msg":None}
		return {"status":True,"msg":csn}
	#def get_csn_config
	
	@try_connect
	def get_csn_data(self):
		aux_base_dn = objects['VariablesManager'].get_variable('LDAP_BASE_DN')
		if aux_base_dn == None:
			return {"status":False,"msg":"LDAP_BASE_DN is not defined"}
		try:
			csn = self.connect_ldapi.search_s(aux_base_dn,ldap.SCOPE_BASE,attrlist=['contextCSN'])[0][1]['contextCSN']
		except Exception as e:
			return {"status":False,"msg":None}
		return {"status":True,"msg":csn}
	#def get_csn_data
	
	
	def get_ldap_password(self):
		password = None
		if os.path.exists(self.LDAP_SECRET1):
			f=open(self.LDAP_SECRET1)
			lines=f.readlines()
			f.close()
			password=lines[0].replace("\n","")
		elif os.path.exists(self.LDAP_SECRET2):
			f=open(self.LDAP_SECRET2)
			lines=f.readlines()
			f.close()
			password=lines[0].replace("\n","")
		else:
			return {'status':False,'msg':'Password is not set'}
		return {'status':True,'msg':password}
	#def get_ldap_password
	
	def active_data_replication(self):
		temp_dn = "".join(random.sample(string.ascii_letters,10))
		base_dn = objects["VariablesManager"].get_variable("LDAP_BASE_DN")
		if base_dn == None:
			return {"status":False,"msg":"LDAP_BASE_DN is not defined"}
		aux_dic = {"ou="+temp_dn+","+base_dn: { "objectClass":["organizationalUnit"], "ou":temp_dn }}
		self.insert_dictionary(aux_dic)
		self.delete_dn(temp_dn)
		return {"status":True,"msg":"Activated replication"}
	#def active_data_replication

	@try_connect
	def enable_syncprov_checkpoint(self,num_changes,minutes):
		dn = 'olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config'
		
		delete_chages = [(ldap.MOD_DELETE,'olcSpCheckpoint')]
		new_changes = [(ldap.MOD_ADD,'olcSpCheckpoint',str(num_changes)+ " " + str(minutes))]
		try:
			self.connect_ldapi.modify_s(dn,self.str_to_bytes(delete_chages))
		except Exception as e:
			pass
		try:
			self.connect_ldapi.modify_s(dn,self.str_to_bytes(new_changes))
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"set checkpoint"}
	#def enable_syncprov_checkpoint

	@try_connect
	def add_rid_data_simple_sync(self, rid, ip, password, rootdn, basedn):
		dn = 'olcDatabase={1}mdb,cn=config'
		'''
			rid
			ip
			rootdn
			password
			basedn
		'''
		template = 'rid=%(rid)03d provider=ldap://%(ip)s/ binddn="%(rootdn)s" bindmethod=simple credentials=%(password)s searchbase="%(basedn)s" type=refreshAndPersist retry="60 +" schemachecking=off tls_reqcert=never'
		try:
			changes = []
			changes.append((ldap.MOD_ADD,'olcSyncrepl',template%{'rid':int(rid),'ip':str(ip),'password':str(password),'rootdn':str(rootdn),'basedn':str(basedn)}))
			try:
				self.connect_ldapi.modify_s(dn,self.str_to_bytes(changes))
			except Exception as e:
				return {"status":False,"msg":str(e)}
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"Server is join"}
	#def add_rid_data_simple_sync

	@try_connect
	def add_updateref_data(self,ip):
		dn = 'olcDatabase={1}mdb,cn=config'
		try:
			changes = []
			changes.append((ldap.MOD_ADD,'olcUpdateRef','ldaps://'+str(ip)))
			try:
				self.connect_ldapi.modify_s(dn,self.str_to_bytes(changes))
			except Exception as e:
				return {"status":False,"msg":str(e)}
		except Exception as e:
			return {"status":False,"msg":str(e)}
		return {"status":True,"msg":"Added updateRef to " + str(ip)}

	def set_master_server_ip(self,ip):
		objects['VariablesManager'].init_variable('MASTER_SERVER_IP',{'ip':ip})
		return {"status":True,"msg":"Variable MASTER_SERVER_IP is set to " + str(ip)}
	#def set_master_server_ip

	def clean_master_server_ip(self):

		objects['VariablesManager'].set_variable("MASTER_SERVER_IP",None)
		return {"status":True,"msg":"Variable MASTER_SERVER_IP is empty"}

	#def clean_master_server_ip

	'''
	Internal methods
	'''
	
	@staticmethod
	def __beint__(integer):
		"""
			return integer from string as far as possible
			examples:
				54foo = 54
				foo54 = None
				54 = 54
		"""
		ret = ""
		for x in integer:
			try:
				int(x)
				ret += x
			except:
				break
		return int(ret) if ret != "" else None
	#def __beint__	

	@staticmethod
	def __becmp__(x,y):
		"""
			
		"""
		if (x == y):
			return 0
		if (x is None ):
			return 1
		if (y is None):
			return -1
		if (int(x) < int(y) ):
			return -1
		if (int(x) > int(y)):
			return 1
	#def __becmp
	
	#@staticmethod
	#def __dncmp__(x,y):
	#	aux_x = x.split(',')
	#	aux_y = y.split(',')
	#	return cmp(len(aux_x),len(aux_y))
	#def __dncmp__
	
	def test_ldapi_connection(self):
		try:
			self.connect_ldapi.search_s('cn=config',ldap.SCOPE_BASE)
			return True
		except:
			return False
	#def test_ldapi_connection
	
	def connection_ldapi(self):
		self.auth=ldap.sasl.sasl('','EXTERNAL')
		try:
			self.connect_ldapi=ldap.initialize('ldapi:///',trace_level=0,bytes_mode=False)
			self.connect_ldapi.protocol_version=3
			self.connect_ldapi.sasl_interactive_bind_s("",self.auth)
			return True
		except:
			self.connect_ldapi = None
			return False
			
	#def connection_ldapi

	def test_ldap_connection(self):
		try:
			self.connection_ldap.search_s('',ldap.SCOPE_BASE)
			return True
		except:
			return False
	#def test_ldap_connection

	def connection_ldap(self):
		try:
			self.connect_ldap=ldap.initialize('ldap://localhost:389',trace_level=0,bytes_mode=False)
			self.connect_ldap.protocol_version=3
			if os.path.exists(self.LDAP_SECRET1):
				f=open(self.LDAP_SECRET1)
				lines=f.readlines()
				f.close()
				password=lines[0].replace("\n","")
			elif os.path.exists(self.LDAP_SECRET2):
				f=open(self.LDAP_SECRET2)
				lines=f.readlines()
				f.close()
				password=lines[0].replace("\n","")
			else:
				self.connect_ldap = None
				return False
			environment_vars = objects["VariablesManager"].get_variable_list(['LDAP_BASE_DN'])
			self.connect_ldap.bind_s("cn=admin,"+environment_vars['LDAP_BASE_DN'],password)
			return True
		except Exception as e:
			self.connect_ldap = None
			return False

	
	def getsalt(self,chars = string.ascii_letters + string.digits,length=16):
		salt = ""
		for i in range(int(length)):
			salt += random.choice(chars)
		return salt
	#def getsalt

	def generate_random_ssha_password(self):
		password="".join(random.sample(string.ascii_letters+string.digits, 10))
		return self.generate_ssha_password(password),password
	#def generate_random_ssha_password

	def generate_ssha_password(self,password):
		salt=self.str_to_bytes(self.getsalt())
		return "{SSHA}" + base64.encodebytes(hashlib.sha1(self.str_to_bytes(password) + salt).digest() + salt).decode('utf-8')
	#def generate_ssha_password  	


if __name__ == '__main__':
	if __DEBUGGING__:
		c = SlapdManager()
		print(c.load_lliurex_schema())
		print(c.enable_tls_communication('/etc/ldap/ssl/slapd.cert','/etc/ldap/ssl/slapd.key'))
		print(c.configure_simple_slapd())
		print(c.open_ports_slapd('10.0.2.254'))
		print(c.reboot_slapd())
		print(c.load_basic_struture())
		print(c.change_admin_passwd('lliurex'))
		# print(c.enable_folders())
		print(c.clean_master_server_ip())
