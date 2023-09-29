#!/usr/bin/env python3

'''
Wireless Technologies and Security (LTAT.04.009) Homework 3
Name: Elisabeth Suits
'''

from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes, toASCIIString, toASCIIBytes
import hashlib

MIFARE_CLASSIC_ATR = "3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A"

cardtype = ATRCardType( toBytes(MIFARE_CLASSIC_ATR) )
cardrequest = CardRequest( timeout=5, cardType=cardtype )
cardservice = cardrequest.waitforcard()

cardservice.connection.connect()

with open("employee1.txt", "r") as file:
	lines = file.readlines()

if len(lines) == 3:
	name = lines[0].strip()
	department = lines[1].strip()
	clearance = lines[2].strip()
	
	first_name = name.split()[0]
	last_name = name.split()[1]

	print(f'Employee Name: {name}')
	print(f'Department: {department}')
	print(f'Clearance Level: {clearance}')
else:
	print("The file does not contain all the required information")

def format_to_bytes(sample_text):
	text_length = len(sample_text)
	mul_of_16 = 16 - (text_length % 16) if (text_length % 16) != 0 else 0
	text_to_send = toASCIIBytes(sample_text) + toBytes("00"*mul_of_16)
	return text_to_send

first_name_to_bytes = toASCIIBytes(first_name)
last_name_to_bytes = toASCIIBytes(last_name)
department_to_bytes = format_to_bytes(department)
clearance_to_bytes = format_to_bytes(clearance)

#SEND APDU
def sendAPDU(APDU):
	data, sw1, sw2 = cardservice.connection.transmit(APDU)
	if [sw1,sw2] == [0x90,0x00]:
		return data
	else:
		print(f'Error sending APDU: {APDU}')
		return "Error"

#WRITE BLOCKS
def writeData():
	# first sector
	sendAPDU([0xFF, 0xD6, 0x00, 4, 16] + format_to_bytes("EMPLOYEE:"))
	sendAPDU([0xFF, 0xD6, 0x00, 5, 16] + first_name_to_bytes)
	sendAPDU([0xFF, 0xD6, 0x00, 6, 16] + last_name_to_bytes)
	sendAPDU([0xFF, 0xD6, 0x00, 8, 16] + format_to_bytes("DEPARTMENT:"))
	block_nr = 9
	for i in range(0,len(department_to_bytes),16):
			if (block_nr <= 10):
				sendAPDU([0xFF, 0xD6, 0x00, block_nr, 16] + department_to_bytes[i:i+16])
				print("kirjutan" + str(block_nr))
			#move to next block for writing
			block_nr+=1
	sendAPDU([0xFF, 0xD6, 0x00, 12, 16] + format_to_bytes("CLEARANCE:"))
	sendAPDU([0xFF, 0xD6, 0x00, 13, 16] + clearance_to_bytes)
	sendAPDU([0xFF, 0xD6, 0x00, 16, 16] + format_to_bytes(uid))
	sendAPDU([0xFF, 0xD6, 0x00, 17, 16] + format_to_bytes(secret))

#def configureSector(Akeys, block_nr):
	#blank
	

#AUTHENTICATION BLOCK
#load key in memory 0x00
sendAPDU([0xFF, 0x82, 0x00, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

#authenticate for needed blocks
for block_nr in range(20):
    sendAPDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_nr, 0x60, 0x00])

print("Creating secret...")
uid = 
secret = hashlib.sha3_256((name+department+clearance).encode()).hexdigest()[:16]
print(f'uid: {uid}, secret: {secret}')

print("Configuring ID card...")


'''
---------------------------------------
Create database entry
-------------------------------------
'''
print("Creating database entry...")


file.close()
print("Process complete")
