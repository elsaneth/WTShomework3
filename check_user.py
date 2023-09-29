'''
Wireless Technologies and Security (LTAT.04.009) Homework 3
Name: Elisabeth Suits
'''

from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes, toASCIIString, toASCIIBytes
from random import randrange
import sys, os, hashlib

MIFARE_CLASSIC_ATR = "3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A"

cardtype = ATRCardType( toBytes(MIFARE_CLASSIC_ATR) )
cardrequest = CardRequest( timeout=5, cardType=cardtype )
cardservice = cardrequest.waitforcard()

cardservice.connection.connect()


def sendAPDU(APDU):
	data, sw1, sw2 = cardservice.connection.transmit( APDU )

	if [sw1,sw2] == [0x90,0x00]:
		return data
	else:
		print(f'Error sending APDU: {APDU}')
		return "Error"

def get_cardUID():
	#APDU to request UID
	uid_apdu =[0xFF, 0xCA, 0x00, 0x00, 0x00]

	#send APDU to card
	data, sw1, sw2 = cardservice.connection.transmit( uid_apdu )
		
	#print results
	return toHexString(data)


door_level = randrange(6)
print(f'Door Entry Level: {door_level}')

#load key in memory 0x00
sendAPDU([0xFF, 0x82, 0x00, 0x00, 0x06] + toBytes('44 44 44 44 44 44'))
sendAPDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 16, 0x60, 0x00])
sector_uid = sendAPDU([0xFF, 0xB0, 0x00, 16, 0x10])
# sector_uid has many trailing \x00 characters
sector_uid_cleaned = toASCIIString(sector_uid).rstrip('\x00')
print("sector uid:", repr(sector_uid_cleaned))

card_uid = get_cardUID()
card_uid_cleaned = card_uid.replace(" ", "")
print("card uid:", repr(card_uid_cleaned))


if sector_uid_cleaned == card_uid_cleaned:
	path = f'./{card_uid_cleaned}.txt'

	if os.path.isfile(path):
		sendAPDU([0xFF, 0x82, 0x00, 0x00, 0x06] + toBytes('11 11 11 11 11 11'))
		sendAPDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 5, 0x60, 0x00])
		first_name = sendAPDU([0xFF, 0xB0, 0x00, 5, 0x10])
		first_name = toASCIIString(first_name)

		sendAPDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 6, 0x60, 0x00])
		last_name = sendAPDU([0xFF, 0xB0, 0x00, 6, 0x10])
		last_name = toASCIIString(last_name)

		name = first_name.rstrip('\x00') + ' ' + last_name.rstrip('\x00')

		print(f'name: {repr(name)}')

		sendAPDU([0xFF, 0x82, 0x00, 0x00, 0x06] + toBytes('22 22 22 22 22 22'))
		sendAPDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 9, 0x60, 0x00])
		department_first_line = sendAPDU([0xFF, 0xB0, 0x00, 9, 0x10])
		department_first_line = toASCIIString(department_first_line)

		sendAPDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 10, 0x60, 0x00])
		department_sec_line = sendAPDU([0xFF, 0xB0, 0x00, 10, 0x10])
		department_sec_line = toASCIIString(department_sec_line)

		department = department_first_line.rstrip('\x00') + department_sec_line.rstrip('\x00')

		print(f'department: {repr(department)}')

		sendAPDU([0xFF, 0x82, 0x00, 0x00, 0x06] + toBytes('33 33 33 33 33 33'))
		sendAPDU([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 13, 0x60, 0x00])
		clearance = sendAPDU([0xFF, 0xB0, 0x00, 13, 0x10])
		clearance = toASCIIString(clearance).rstrip('\x00')

		print(f'clearance: {repr(clearance)}')

		card_secret = hashlib.sha3_256((name+department+clearance).encode()).hexdigest()[:16]

		with open(path, "r") as file:
			lines = file.readlines()
			file_secret = lines[0].strip()
			print("card secret: ", card_secret)
			print("file secret: ", file_secret)
			if card_secret == file_secret:	
				if int(clearance) >= door_level:
					print(f'Employee: {first_name} {last_name}')
					print(f'Department: {department}')
					print(f'You are cleared for entry!')
				else:
					sys.exit("Access Denied!")		
			
			else:
				sys.exit("Access Denied! Secret codes does not match")
	
	else:
		sys.exit("Access Denied! Card not in database")	

else:
	sys.exit("Access Denied! Invalid card format")