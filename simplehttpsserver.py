#!/usr/bin/python

import sys
import os
import BaseHTTPServer, SimpleHTTPServer
import ssl
import subprocess
import shlex
import socket

OPENSSL_CONF_TEMPLATE="""
HOME			= .
RANDFILE		= $ENV::HOME/.rnd
oid_section		= new_oids
[ new_oids ]
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7
[ ca ]
default_ca	= CA_default		# The default ca section
[ CA_default ]
dir		= ./demoCA		# Where everything is kept
certs		= $dir/certs		# Where the issued certs are kept
crl_dir		= $dir/crl		# Where the issued crl are kept
database	= $dir/index.txt	# database index file.
					# several certs with same subject.
new_certs_dir	= $dir/newcerts		# default place for new certs.
certificate	= $dir/cacert.pem 	# The CA certificate
serial		= $dir/serial 		# The current serial number
crlnumber	= $dir/crlnumber	# the current crl number
					# must be commented out to leave a V1 CRL
crl		= $dir/crl.pem 		# The current CRL
private_key	= $dir/private/cakey.pem# The private key
RANDFILE	= $dir/private/.rand	# private random number file
x509_extensions	= usr_cert		# The extensions to add to the cert
name_opt 	= ca_default		# Subject Name options
cert_opt 	= ca_default		# Certificate field options
copy_extensions = copy
default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering
policy		= policy_match
[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
[ req ]
default_bits		= 2048
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	= v3_ca	# The extensions to add to the self signed cert
string_mask = utf8only
[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= AU
countryName_min			= 2
countryName_max			= 2
stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some-State
localityName			= Locality Name (eg, city)
0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= Internet Widgits Pty Ltd
organizationalUnitName		= Organizational Unit Name (eg, section)
commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64
emailAddress			= Email Address
emailAddress_max		= 64
[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20
unstructuredName		= An optional company name
[ usr_cert ]
basicConstraints=CA:FALSE
nsComment			= "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
[ v3_ca ]
subjectAltName      = @alternate_names
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = digitalSignature, keyEncipherment
[ crl_ext ]
authorityKeyIdentifier=keyid:always
[ proxy_cert_ext ]
basicConstraints=CA:FALSE
nsComment			= "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo
[ tsa ]
default_tsa = tsa_config1	# the default TSA section
[ tsa_config1 ]
dir		= ./demoCA		# TSA root directory
serial		= $dir/tsaserial	# The current serial number (mandatory)
crypto_device	= builtin		# OpenSSL engine to use for signing
signer_cert	= $dir/tsacert.pem 	# The TSA signing certificate
					# (optional)
certs		= $dir/cacert.pem	# Certificate chain to include in reply
					# (optional)
signer_key	= $dir/private/tsakey.pem # The TSA private key (optional)
signer_digest  = sha256			# Signing digest to use. (Optional)
default_policy	= tsa_policy1		# Policy if request did not specify it
					# (optional)
other_policies	= tsa_policy2, tsa_policy3	# acceptable policies (optional)
digests     = sha1, sha256, sha384, sha512  # Acceptable message digests (mandatory)
accuracy	= secs:1, millisecs:500, microsecs:100	# (optional)
clock_precision_digits  = 0	# number of digits after dot. (optional)
ordering		= yes	# Is ordering defined for timestamps?
				# (optional, default: no)
tsa_name		= yes	# Must the TSA name be included in the reply?
				# (optional, default: no)
ess_cert_id_chain	= no	# Must the ESS cert id chain be included?
				# (optional, default: no)
"""

DESCRIPTION="""Usage: {0} <ip> <port>

In summary, This script will generate a HTTPS Server indexing the current directory for serving page requests.

It utilizes openssl to generate self-signed ssl keys and then launch the SSL server utilizing the key. The directory in which the python file is present is indexed by the server for serving requests. Note that 2 new files are created by the server: 
    * SSL Certificate: for the HTTPS Server, self-signed
    * OpenSSL conf file: to generate self-signed cert with IP in SAN
It will also attempt to clean up the generate ssl keys, when interrupted with CTRL + C.

Arguments:
    ip=IP to put on the SSL cert Subject Name
    port=SSL port on which to run the ssl server

Requirements:
    * /usr/bin/openssl (OpenSSL Linux Binary)
    * /tmp/ must be writable by the user running the script

Examples:
    * To start HTTPS Server on port 443 on the localhost in current dir, simple move {0} to the appropriate server directory and run, 
        {0} 127.0.0.1 443
        
      On client side, execute following to download test.txt from the server dir:
         wget --no-check-certificate https://127.0.0.1/test.txt
                OR 
         curl -k https://127.0.0.1/test.txt

Credits:
    * jww, for providing info on stackoverflow on how to generate conf 
      file for modifying conf file to generate SSL self-signed SAN cert.
      This cert ensure that the hostname matches existing IP, reducing
      one warning generated by http request tools like wget, curl. 
      Original post is here:
        https://stackoverflow.com/questions/21488845/how-can-i-generate-a-self-signed-certificate-with-subjectaltname-using-openssl

    * dergachev, for the core on how to wrap SimpleHTTPServer in HTTPS.
      Original script available here:
        https://gist.github.com/dergachev/7028596""".format(sys.argv[0])

if len(sys.argv) < 3:
    print DESCRIPTION
    sys.exit(1)

ip = sys.argv[1]

try:
    port = int(sys.argv[2])
    if port <= 0:
        raise ValueError("Invalid value provided")
except Exception as e:
    print "[-] Error generated: {0}".format(str(e))
    sys.exit(2)

try:
    print "[*] Preparing the openssl conf file for generating self-signed cert with SAN"
    conf_file_tmpl_with_ip = OPENSSL_CONF_TEMPLATE + "\n\n[ alternate_names ]\n"
    conf_file_tmpl_with_ip += "IP.1 = {0}\n".format(ip)
    
    print "[*] Creating new conf file"
    with open("/tmp/conf_file.config", "wb+") as f:
        f.write(conf_file_tmpl_with_ip)
        
except Exception as e:
    print "[-] Error when read openssl cnf file template: {0}".format(str(e))
    sys.exit(3)

print "[*] Generating the SSL key and cert via openssl"
p = subprocess.Popen(shlex.split("/usr/bin/openssl req -config /tmp/conf_file.config -new -x509 -keyout /tmp/server.pem -out /tmp/server.pem -days 365 -nodes -subj \"/C=US/ST=Denial/L=Springfield/O=Dis/CN={0}\"".format(ip)), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
(out, err) = p.communicate()
print "Output: {0}\n{1}".format(out, err)

try:
    print "[*] Launching the HTTPS Server on  ({0},{1})".format(ip, port)
    httpd = BaseHTTPServer.HTTPServer((ip, port), SimpleHTTPServer.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile='/tmp/server.pem', server_side=True)
    httpd.serve_forever()
except socket.error as e:
    print "[-] socket.error: {0}".format(str(e))
except KeyboardInterrupt as e:
    print "[-] Cleaning up SSL cert"
    os.remove("/tmp/server.pem")

    print "[-] Cleaning up config file"
    os.remove("/tmp/conf_file.config")
