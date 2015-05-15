require 'openssl'
require 'digest/sha1'

# external gems
require 'net/ssh'
require 'gpgme'
# this is a serach script I am creating to be able to search multiple machines. originally i wrote this in python but i have decided to switch to ruby in order to make life easier for everyone else.
@iv = nil

# TODO: add the capibilities to communicate with docker workers... how would one do this?
# TODO: format this data in json form. so you can input what you want done in json, and you get the return results in json.
def get_machines(username=nil)
	# TODO: you need to pass in json or yaml documentation in place of hard coded hashes.
	if username == nil
		username = "random"
	end
	machines = {
		# special case where this should be replaced by the number of workers -->> 
		"cluster_name01"=>[],
		# ...
		"cluster_name0N"=>[]
	}
	return username , machines
end

def run_command(username, password, node, commands)
	Net::SSH.start(node, username, :password=>password) do |ssh|
		output = ssh.exec!("hostname")
		commands.each do |command|
			# TODO: add a rescue statement here to make sure that comand is actually correct
			stdout = ""
			ssh.exec!(command) do |channel, stream, data|
				stdout << data if stream == :stdout
			end
			# TODO: pass this mesage somewhere and handle the data appropriatly.
			puts "stdout: "+stdout.to_s
		end
	end
end

# TODO: create a method for actually returning the data from your search. then parsing/ transofrming it into user readable data.
def run_commands(username, password, machines, commands=[])
	machines.each do |machine, nodes|
		nodes.each do |node|
			run_command(username, password, node, commands)
		end
		puts "machine: "+machine.to_s
		# puts "machine = ", machine
	end
end

def encrypt_file(filename, password, curr_key)
	cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
	cipher.encrypt
	# you will need to store these for later, in order to decrypt your data
	key = Digest::SHA1.hexdigest(curr_key.to_s)
	iv = cipher.random_iv

	# load them into the cipher
	cipher.key = key
	cipher.iv = iv
	# <@>
	w_iv = File.open('iv.x','w')
	w_iv.write(iv)
	w_iv.close()
	# <@>

	# encrypt the message
	encrypted = cipher.update(password.to_s)
	encrypted << cipher.final

	puts "encrypted #{encrypted}\n"

	w = File.open(filename, "w")
	w.write(encrypted)
	w.close()
	puts "File: #{filename} written!"

	# XXX: this is a temporary workaround to get this up and running
	@iv = iv
end

def unencrypt_file(filename, curr_key)
	# now we create a sipher for decrypting
	encrypted = File.open(filename,'r')
	s_encrypted = ""
	encrypted.each do |e|
		s_encrypted += e
	end
        key = Digest::SHA1.hexdigest(curr_key.to_s)

	cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
	cipher.decrypt
	cipher.key = key
	if @iv != nil
		cipher.iv = @iv
	elsif File.exist?("iv.x")
		f = File.open("iv.x","rb")
		iiv = ""
		f.each do |fi|
			iiv+=fi
		end
		cipher.iv = iiv
	else
		# TODO: use a better Exception then this
		puts "You need to regenerate your key or locate the `iv.x` file"
		raise Exception
	end
	# and decrypt it
	decrypted = cipher.update(s_encrypted)
	decrypted << cipher.final
	# puts "decrypted: #{decrypted}\n"

	return decrypted
end

# go = false
go = true
# TODO: figure out how to enter in password for a sudo command
commands = ["ls -la", "locate .erb"]

if go
	#encrypt_file("super-secret-file","linux","")
	#unencrypt_file("super-secret-file","")
	username, machines = get_machines()
	run_commands(username, unencrypt_file("super-secret-file", ""), machines, commands)
end
