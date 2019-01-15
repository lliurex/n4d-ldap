#!/usr/bin/env python
import ldap
import xmlrpclib
import sys
import os.path
import lliurex.variables.sambasid as getsambasid


class UpdateLdapUsers:
    def __init__(self, server, path_password):
        self.n4d = xmlrpclib.ServerProxy('https://' + server + ':9779')
        self.ldap_server = 'ldap://' + server + ':389'
        self.ldap_password = self.get_password(path_password)
        self.n4d_password = self.get_password('/etc/n4d/key')

    def get_password(self, path_password):
        if os.path.exists(path_password):
            f = open(path_password)
            lines = f.readlines()
            f.close()
            password = lines[0].replace("\n", "")
            return password
        else:
            return None

    def init_vars(self):
        self.local_sambaSID = self.n4d.get_variable(self.n4d_password, 'VariablesManager', 'SAMBASID')
        self.ldap_basedn = self.n4d.get_variable(self.n4d_password, 'VariablesManager', 'LDAP_BASE_DN')

    def get_conection(self):

        if self.ldap_password == None:
            return None
        connect_ldap = ldap.initialize(self.ldap_server, trace_level=0)
        connect_ldap.protocol_version = 3
        try:
            connect_ldap.bind_s("cn=admin," + self.ldap_basedn, self.ldap_password)
        except Exception as e:
            pass
        return connect_ldap

    def update(self):
        connect_ldap = self.get_conection()
        if connect_ldap == None:
            return None
        items = connect_ldap.search_s(self.ldap_basedn, ldap.SCOPE_SUBTREE)
        list_update_dn = []
        #get dn hasn't equal sambasid
        for x in items:
            if x[1].has_key('sambaSID'):
                sambasidsplit = x[1]['sambaSID'][0].split('-')
                basesid = '-'.join(sambasidsplit[:-1])
                aux = ''
                if self.local_sambaSID != basesid:
                    aux = self.local_sambaSID + '-' + sambasidsplit[-1]
                    list_update_dn.append([x[0], aux])
        #update dn
        for dn in list_update_dn:
            update_sambasid = [(ldap.MOD_REPLACE, 'sambaSID', dn[1])]
            try:
                connect_ldap.modify_s(dn[0], update_sambasid)
            except:
                pass
        return True

    def run(self):
        self.init_vars()
        self.update()


if __name__ == '__main__':
    update_ldap = UpdateLdapUsers('localhost', '/etc/lliurex-secrets/passgen/ldap.secret')
    update_ldap.run()
