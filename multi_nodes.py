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

__author__ = "Alex Balzer"
__version__ = "0.1.0"

# TODO: need to create the method that will search the `dirs` that you specify

def generate_json_file():
	# TODO:
	# generates a base image for the json file
	pass

def connect_to_server(server_name, uname, passwd, key=None):
	ssh = pm.SSHClient()
	try:
		if key == None:
			ssh.set_missing_host_key_policy(pm.AutoAddPolicy())
			ssh.connect( server_name, username=uname, password=passwd )
			# print ssh
			return ssh
		else:
			ssh.set_missing_host_key_policy(pm.AutoAddPolicy())
			ssh.connect( server_name, username=uname, password=passwd , pkey=key)
			return ssh
	except:
		return None

class fileinfo(object):
	"""
	basic fileinfo object that gives all the relative information
	"""
	def __init__(self,filename,filedata):
		self.filename = filename
		self.filedata = filedata
		self.important_lines = []

	def update_lines(self,n):
		"""
		add a line number with relative information
		"""
		self.important_lines.append(n)

def _check_file(filepath, search_string, regex_pattern):
	# TODO: implement this function to open a file and iterate through it. if you find a match then retrun those results.
	r = open(filepath,'r').readlines()
	results = []
	for i in r:
		if search_string == None:
			pass
		else:
			if search_string in i:
				results.append(i)
		

def search_dir(directory, search_string=None, regex_pattern=None,file_types=None):
	"""
	file_types = None means that you search all files you come across
	"""
	# TODO: create a non-recursive solution to this. in case you only want to search that level of the directory
	for root, dirs, files in os.walk(directory):
		for i in files:
			if file_types == None:
				# check all files
				_check_file(os.path.join(root,i) , search_string , regex_pattern)
			elif isinstance(file_types, list):
				for ftype in file_types:
					if i.endswith(ftype):
						_check_file( os.path.join(root,i) , search_string , regex_pattern )
			else:
				return Exception # TODO: need to create a custom exception here.

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
	w = open('secret_key.x15','w')
	w.write(secret)
	print "secret key length = ", len(secret)
	return encoded , secret

# TODO: create a file that can be used as your decryption method.
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

def execute_command(ssh, command):
	i,o,e = ssh.exec_command(command)
	# TODO: check all three values and handle accordingly

if __name__ == "__main__":
	import sys
	l = sys.argv[1:] # list of all the nodes to connect to
	json_file = json.loads( open(l[0],'r').read() )
	# TODO: create an exception that will handle bad json nodes, that for one reason or another are not working.
	for node in json_file.iterkeys():
		if 'pkey' in node: # you have a node that uses a key to connect
			pass
			# ssh_conn = connect_to_server()
			# search_dir()
		else:
			# TODO: need to come up with a better way to generate and make sense of these attributs. currently its to flat.
			print node, json_file[node]['uname'] , json_file[node]['passwd']
			# decrypt the password
			key = raw_input("please enter in the file to decrypt your password:\n")
			try:
				key_file = open(key,'r').read()
			except:
				key_file = None
			print 'length of the key = ',len(key_file), '\nkey = ',key_file
			json_file[node]['passwd'] = decrypt( json_file[node]['passwd'] , key_file )
			ssh = connect_to_server(node, json_file[node]['uname'] , json_file[node]['passwd'])
			dirs = ['/']
			if 'dirs' in json_file[node]:
				dirs = json_file[node]['dirs'] # need to make sure that this is a list
			for i in dirs:
				search_dir(i)
			i,o,e = ssh.exec_command('ls -la')
			print o.read()
			print ssh
			# search_dir()
