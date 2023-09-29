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

first_name_to_bytes = toASCIIBytes(first_name)
last_name_to_bytes = toASCIIBytes(last_name)
department_to_bytes = format_to_bytes(department)
clearance_to_bytes = format_to_bytes(clearance)

# SEND APDU
def sendAPDU(APDU):
	data, sw1, sw2 = cardservice.connection.transmit(APDU)
	if [sw1,sw2] == [0x90,0x00]:
		return data
	else:
		print(f'Error sending APDU: {APDU}')
		return "Error"

# WRITE BLOCKS
def writeData(block_nr):
	# first sector
	if (block_nr in range (4,7)):
		sendAPDU([0xFF, 0xD6, 0x00, 4, 16] + format_to_bytes("EMPLOYEE:"))
		sendAPDU([0xFF, 0xD6, 0x00, 5, 16] + first_name_to_bytes)
		sendAPDU([0xFF, 0xD6, 0x00, 6, 16] + last_name_to_bytes)
	
	# second sector
	elif (block_nr in range(9,11)):
		sendAPDU([0xFF, 0xD6, 0x00, 8, 16] + format_to_bytes("DEPARTMENT:"))
		block_nr = 9
		for i in range(0,len(department_to_bytes),16):
				if (block_nr <= 10):
					sendAPDU([0xFF, 0xD6, 0x00, block_nr, 16] + department_to_bytes[i:i+16])
					print("kirjutan" + str(block_nr))
				#move to next block for writing
				block_nr+=1
	
	# third sector
	elif (block_nr in range(12, 15)):
		sendAPDU([0xFF, 0xD6, 0x00, 12, 16] + format_to_bytes("CLEARANCE:"))
		sendAPDU([0xFF, 0xD6, 0x00, 13, 16] + clearance_to_bytes)
	
	# fourth sector
	elif (block_nr in range(16, 19)):
		sendAPDU([0xFF, 0xD6, 0x00, 16, 16] + format_to_bytes(uid))
		sendAPDU([0xFF, 0xD6, 0x00, 17, 16] + format_to_bytes(secret))

# WRITE A-KEY
def configureSector(Akey, block_nr):
	if (block_nr%4) == 3 and block_nr < 20:
		sendAPDU([0xFF, 0xD6, 0x00, block_nr, 16] + format_to_bytes(Akey + " ff 07 80 69 ff ff ff ff ff ff"))

print("Creating secret...")
uid = "hds"
secret = hashlib.sha3_256((name+department+clearance).encode()).hexdigest()[:16]
print(f'uid: {uid}, secret: {secret}')
print("secret bytes: " + format_to_bytes(secret))

print("Configuring ID card...")
print("Creating database entry...")

# WRITE SECRET TO NEW FILE UID
with open(f'{uid}.txt', 'w') as f:
    f.write(f'Secret: {secret}')


file.close()
print("Process complete")