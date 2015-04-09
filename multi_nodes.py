"""
This file reads in a json specified file that gives all nodes that you want to search for information
it then tries to connect to each.
if it connects it queries the os for the given parameters in the given folders.
it will make life way easier because manually sshing into boxes one by one is time consuming.

reads in a json file that gives server info. 
{
 'nodename':{
  'uname': 'johnsmith',
  'passwd': 'encrypted_password'
  'pkey': 'blah blah blah'
 },
 ...,
 'nodename_x':{
  'uname': 'lucyjones',
  'passwd': 'encrypted_password'
 }
}
"""

import paramiko as pm
import json

import os
import argparse
import base64
from Crypto.Cipher import AES
import re

def generate_json_file():
	# generates a base image for the json file
	pass

def connect_to_server(server_name, uname, passwd, key=None):
	ssh = pm.SSHClient()
	try:
		if key == None:
			print 'a'
			ssh.set_missing_host_key_policy(pm.AutoAddPolicy())
			ssh.connect( server_name, username=uname, password=passwd )
			print ssh
			return ssh
		else:
			ssh.set_missing_host_key_policy(pm.AutoAddPolicy())
			ssh.connect( server_name, username=uname, password=passwd , pkey=key)
			return ssh
	except:
		return None

def search_dir(directory, search_string=None, regex_pattern=None):
	for root, dirs, files in os.walk(directory):
		pass

# --------------------------------------------------------------------------------------------------
# borrowed from "http://sentdex.com/sentiment-analysisbig-data-and-python-tutorials-algorithmic-trading/encryption-and-decryption-in-python-code-example-with-explanation/"
# NOTE: both of the encryption methods are outdated and need to mature to become more secure.
def encrypt(data):
	block_size = 16
	padding = '{'
	pad = lambda s: s + (block_size - len(s) % block_size) * padding
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	secret = os.urandom(block_size)
	print 'Encryption Key Secret:',secret
	cipher = AES.new(secret)
	encoded = EncodeAES(cipher, data)
	print 'Encrypted String:',encoded
	return encoded

def decrypt(data,key='not_random'):
	PADDING = '{'
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	#Key is FROM the printout of 'secret' in encryption
	#below is the encryption.
	encryption = data
	#key = ''
	cipher = AES.new(key)
	decoded = DecodeAES(cipher, encryption)
	print 'Decoded:',decoded
	return decoded

# --------------------------------------------------------------------------------------------------

if __name__ == "__main__":
	import sys
	l = sys.argv[1:] # list of all the nodes to connect to
	json_file = json.loads( open(l[0],'r').read() )
	for node in json_file.iterkeys():
		if 'pkey' in node: # you have a node that uses a key to connect
			pass
			# ssh_conn = connect_to_server()
			# search_dir()
		else:
			print node, json_file[node]['uname'] , json_file[node]['passwd']
			ssh = connect_to_server(node, json_file[node]['uname'] , json_file[node]['passwd'])
			i,o,e = ssh.exec_command('ls -la')
			print o.read()
			print ssh
			# search_dir()
