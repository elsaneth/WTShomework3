'''
Wireless Technologies and Security (LTAT.04.009) Homework 3
Name: Elisabeth Suits
'''

from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes, toASCIIString, toASCIIBytes
import hashlib

MIFARE_CLASSIC_ATR = "3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A"

cardtype = ATRCardType(toBytes(MIFARE_CLASSIC_ATR))
cardrequest = CardRequest(timeout=5, cardType=cardtype)
cardservice = cardrequest.waitforcard()

cardservice.connection.connect()

def format_to_bytes(sample_text):
	text_length = len(sample_text)
	mul_of_16 = 16 - (text_length % 16) if (text_length % 16) != 0 else 0
	text_to_send = toASCIIBytes(sample_text) + toBytes("00"*mul_of_16)
	return text_to_send

# SEND APDU
def send_APDU(APDU):
	data, sw1, sw2 = cardservice.connection.transmit(APDU)
	if [sw1,sw2] == [0x90,0x00]:
		return data
	else:
		print(f'Error sending APDU: {APDU}')
		return "Error"

def write_block(block_nr, bytes):
	send_APDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_nr, 0x61, 0x00])
	send_APDU([0xFF, 0xD6, 0x00, block_nr, 16] + bytes)

# WRITE/AUTHENTICATE BLOCKS
def write_sector(sector_nr):
	# load key in memory 0x00
	send_APDU([0xFF, 0x82, 0x00, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
	# first sector
	if (sector_nr == 1):
		write_block(4, format_to_bytes("EMPLOYEE:"))
		write_block(5, first_name_to_bytes)
		write_block(6, last_name_to_bytes)
	
	# second sector
	elif (sector_nr == 2):
		write_block(8, format_to_bytes("DEPARTMENT:"))
		block_nr = 9
		for i in range(0,len(department_to_bytes),16):
				if (block_nr <= 10):
					write_block(block_nr, department_to_bytes[i:i+16])
				#move to next block for writing
				block_nr+=1
	
	# third sector
	elif (sector_nr == 3):
		write_block(12, format_to_bytes("CLEARANCE:"))
		write_block(13, clearance_to_bytes)
	
	# fourth sector
	elif (sector_nr == 4):
		write_block(16, format_to_bytes(uid_cleaned))
		write_block(17, format_to_bytes(secret))

# WRITE A-KEY
def configure_sector(Akey, block_nr):
    if (block_nr % 4) == 3 and block_nr < 20:
        print("Configuring sector ", str(block_nr))
        print("writing ", toHexString(toBytes(Akey + " 78 77 88 41 ff ff ff ff ff ff")))
        send_APDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_nr, 0x60, 0x00])
        send_APDU([0xFF, 0xD6, 0x00, block_nr, 0x10] + toBytes(Akey + " 78 77 88 41 ff ff ff ff ff ff"))

def get_cardUID():
	#APDU to request UID
	uid_apdu =[0xFF, 0xCA, 0x00, 0x00, 0x00]

	#send APDU to card
	data, sw1, sw2 = cardservice.connection.transmit( uid_apdu )

	#print results
	return toHexString(data)

# RUN PROGRAM
file_name = "employee1.txt"
with open(file_name, "r") as file:
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

first_name_to_bytes = format_to_bytes(first_name)
last_name_to_bytes = format_to_bytes(last_name)
department_to_bytes = format_to_bytes(department)
clearance_to_bytes = format_to_bytes(clearance)

uid = get_cardUID()
uid_cleaned = uid.replace(" ", "")
print("uid:" + uid_cleaned)

print("Creating secret...")
secret = hashlib.sha3_256((name+department+clearance).encode()).hexdigest()[:16]
print(f'uid: {uid}, secret: {secret}')
print(format_to_bytes(secret))

print("Configuring ID card...")
write_sector(1)
write_sector(2)
write_sector(3)
write_sector(4)

configure_sector("11 11 11 11 11 11", 7)
configure_sector("22 22 22 22 22 22", 11)
configure_sector("33 33 33 33 33 33", 15)
configure_sector("44 44 44 44 44 44", 19)

print("Creating database entry...")
with open(f'{uid_cleaned}.txt', 'w') as f:
    f.write(secret)

for i in range(0,20):
	send_APDU([0xFF, 0x82, 0x00, 0x00, 0x06] + toBytes("ff ff ff ff ff ff"))
	send_APDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, i, 0x61, 0x00])

	block_data = send_APDU([0xFF, 0xB0, 0x00, i, 0x10])
	print(f'Block {i:02d}: {toHexString(block_data)} | {toASCIIString(block_data)}')

file.close()
print("Process complete")