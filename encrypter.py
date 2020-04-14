#!/usr/bin/env python3.8

import os, struct, sys, argparse, hashlib
from Crypto.Cipher import AES
from random import seed
from random import randint

parser=argparse.ArgumentParser(
    description='''This is a Python Command Line Encryption Tool''')
parser.add_argument('-e','--encrypt', action='store_true', help='Encrypt the given file')
parser.add_argument('-d','--decrypt', action='store_true', help='Decrypt the given file')
parser.add_argument('-p','--password', help='Sets the Password for encryption or decryption')
parser.add_argument('-k','--key-file', dest='keyfile', help='Sets the key file to encrypt or decript with')
parser.add_argument('-i','--input-file', dest='ifile', help='The input file')
parser.add_argument('-o','--output-file', dest='ofile', help='The output file')
parser.add_argument('-g','--generate',action='store_true', help='Generates a new key File')
parser.add_argument('-v','--version',action='store_true',help='Print the program version')
parser.add_argument('-l','--length',default=1024,help='Sets the length of the generated key')
args = parser.parse_args()


def print_version():
	print("Python AES Encrypter v1.2")
	sys.exit()

def generate_key_file(key_length,file_name):
	
	feed='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,?;.:><!%/=()~^-_*'
	key=''
	
	for x in range(int(key_length)):
		value=randint(0,len(feed)-1)
		key+= str(feed[value])

	#print("Key: "+key)
	with open(file_name, "w") as text_file:
    		text_file.write(key)


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'
    iv='D7{c7pP!}70;K-3a'
    #iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    #debug values
    #print("length of key: "+str(len(key)))
    #print("length of IV: "+str(len(iv)))

	
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            #outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk +=b' ' * (16 - len(chunk) % 16)
			
                outfile.write(encryptor.encrypt(chunk))

def readfile(path):
	with open(path, 'r') as file:
		data = file.read()
		return data

def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    iv='D7{c7pP!}70;K-3a'
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        #iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


#Checks the file extension to decide encrypt or decrypt a file
def check_extension(input_ext):
	if input_ext.endswith('.enc'):
		return 'd'
	else:
		return 'e'


def get_hash_key(input_value):
	passwd = input_value.encode('utf-8',errors = 'strict')
	key = hashlib.sha256(passwd).digest()
	return key

# innentől van a main
def main():
	
	#Declare the variables
	#The output file name
	output_file=''
	#the input file name
	input_file=''
	#The password to encrypt or decrypt with
	passwd=''
	#The key string to encrypt or decrypt with
	keystring=''
	#The Encyption With variable, the default value is p = password
	enc_with='p'
	# args Encrypt and Decrypt values
	encrypt= args.encrypt
	decrypt= args.decrypt
	#Key to encrypt or decrypt with, this is a 32 byte lenght key
	hash_key=''
	
	
	
	#Check The program Version
	if args.version:
		print_version()
	
	#The GENERATE Method
	#in this case the program avoids all other arguments and generate a new key file.	
	if args.generate:
		length=1024
		if args.length:
			length = args.length
		
		if args.ofile:
			output_file=args.ofile
		else:
			output_file='encrypter.key'

		generate_key_file(length,output_file)
		print("Generated Key Length: "+str(length))
		print("Generated Key File: "+output_file)
		sys.exit()

	
	
	# Check the input file is exists or not. If not promt an error.
	if args.ifile:
		input_file=args.ifile
	else:
		print("The program needs an input file.")
		sys.exit()

	
	
	
	
	
	# if the user give password and key file
	if args.password and args.keyfile:
		print("The program can use only one parameter from the followings [Password, Keyfile]")	
		sys.exit()


	# if the stupid user type -d and -e both
	if encrypt==True and decrypt==True:
		print("The program can Encrypt a file OR Decrypt it. It doesn't work at the same time.")
		sys.exit()



	#Decide which operation is needed, because the user did not given -e and -d parameters.. fck noob users	
	if encrypt==False and decrypt==False:
		enc_with=check_extension(args.ifile)
		if enc_with=='e':
			encrypt=True
			decrypt=False
		else:
			decrypt=True
			encrypt=False

	
	

	#use password
	if args.password:
		passwd=args.password;
		hash_key=get_hash_key(passwd)

	# use key file content
	if args.keyfile:
		keystring=readfile(args.keyfile)
		hash_key=get_hash_key(keystring)
	#Debug
	"""print("Encrypt: "+str(encrypt))
	print("Decrypt: "+str(decrypt))
	print("args.Password: "+str(args.password))
	print("args.Keyfile: "+str(args.keyfile))
	print("Hash Key: "+str(hash_key))
	print("Password: "+str(passwd))
	"""
	

	if encrypt:
				
		# check the passed argument files
		if args.ofile:
			if args.ofile.endswith('.enc'):
				output_file=args.ofile
			else:
				putput_file=args.ofile+'.enc'
		else:
			output_file=input_file+'.enc'
		
		#if password and keyfile not defined we promt a questin and wait the input password.
		if args.password is None and args.keyfile is None:
			p=input("Enter a password: ")
			r=input("ReEnter a password: ")
			if(p == r):
				passwd=p
				hash_key=get_hash_key(passwd)
	
		

		encrypt_file(hash_key,input_file,output_file)
		print("The input file "+input_file+" successfully encrypted!")
		print("The encrypted file name is: "+output_file)

	if decrypt:
		if args.password is None and args.keyfile is None:
			passwd=input("Enter a password: ")
			hash_key=get_hash_key(passwd)

		if args.ofile:
			output_file=args.ofile
			decrypt_file(hash_key,input_file,output_file)
		else:
			decrypt_file(hash_key,input_file)
		
		print("The input file "+input_file+" successfully decrypted!")
		print("The decrypted file name is: "+ input_file[:-4])


if __name__ == "__main__":
	main()
