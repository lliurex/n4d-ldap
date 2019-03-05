#!/bin/bash

LDIF_FILE=$(mktemp)

cat > $LDIF_FILE << EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcDbMaxSize
olcDbMaxSize: 209715200
EOF
    
ldapmodify -Y EXTERNAL -H ldapi:// -f $LDIF_FILE || true

rm -rf $LDIF_FILE
