
from time import time
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os, sys
import string
import random

BLOCK_SIZE = 16

def attack_message(msg):

	cipherfake=[0] * 16
	plaintext = [0] * 16
	current = 0
	message=""

	#I devide the list of bytes in blocks, and I put them in another list
	number_of_blocks = int(len(msg)/BLOCK_SIZE)
	blocks = [[]] * number_of_blocks
	for i in (range(number_of_blocks)):
		blocks[i] = msg[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE]
	count = 0
	for z in range(len(blocks)-1):  #for each message, I calculate the number of block
		for itera in range (1,17): #the length of each block is 16. I start by one because than I use its in a counter
			for v in range(256):
				count += 1
				print(f"{count} Bloc {z} Char {itera} Try {v}")
				cipherfake[-itera]=v
				if is_padding_ok(bytes(cipherfake)+blocks[z+1]): #the idea is that I put in 'is_padding_ok' the cipherfake(array of all 0) plus the last block
					print("good")											 #if the function return true I found the value
					current=itera
					plaintext[-itera]= v^itera^blocks[z][-itera]
					break

			for w in range(1,current+1):
				cipherfake[-w] = plaintext[-w]^itera+1^blocks[z][-w] #for decode the second byte I must set the previous bytes with 'itera+1'


		for i in range(16):
			if plaintext[i] >= 32:
				char = chr(int(plaintext[i]))
				message += char

	return str.encode(message)

def is_padding_ok(msg):
	msg = msg.hex()
	io.sendline(msg.encode())
	resp = io.recvline()
	return not b"idek" in resp

def get_enc():
	io.recvline()
	enc_token = io.recvline().decode()
	print(enc_token)
	enc_token = bytes.fromhex(enc_token)
	return enc_token[:BLOCK_SIZE], enc_token[BLOCK_SIZE:]

host = ("crypto.challs.pragyanctf.tech", 5001)
local = False
with process(['python3', 'Kinda_AESthetic.py']) if local else remote(*host) as io:
	IV, enc_token = get_enc()
	tic = int(time.time())
	token = attack_message(IV+enc_token).strip()
	
	context.log_level = "debug"
	print(f"Token: {token.decode()}")

	tamp = pad(token + b"gg", BLOCK_SIZE)
	tamp = xor(tamp, pad(token, BLOCK_SIZE))
	tamp = xor(tamp, IV)
	tamp = tamp + enc_token
	io.sendline(tamp.hex().encode())

	password = io.recvline().strip()
	print(f"Password: {password.decode()}")
	tamp = pad(b"gg", BLOCK_SIZE)
	tamp = xor(tamp, pad(token, BLOCK_SIZE))
	tamp = xor(tamp, IV)
	tamp = tamp + enc_token
	io.sendline(tamp.hex().encode())

	print(io.recvline())
	tamp = pad(password, BLOCK_SIZE)
	tamp = xor(tamp, pad(token, BLOCK_SIZE))
	tamp = xor(tamp, IV)
	tamp = tamp + enc_token
	io.sendline(tamp.hex().encode())
	print(io.recvline())
