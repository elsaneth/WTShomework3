#!/usr/bin/env python3

'''
Wireless Technologies and Security (LTAT.04.009) Homework 3
Name:
'''

from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes, toASCIIString, toASCIIBytes
from random import randrange
import sys, os, hashlib

MIFARE_CLASSIC_ATR = ""

cardtype = ATRCardType( toBytes(MIFARE_CLASSIC_ATR) )
cardrequest = CardRequest( timeout=5, cardType=cardtype )
cardservice = cardrequest.waitforcard()

cardservice.connection.connect()


def sendAPDU(APDU):
	data, sw1, sw2 = cardservice.connection.transmit( APDU )

	if [sw1,sw2] == [0x90,0x00]:
		return data
	else:
		#print(f'Error sending APDU: {APDU}')
		return "Error"
	


door_level = randrange(6)
print(f'Door Entry Level: {door_level}')

'''
---------------------------------------
read authentication block
-------------------------------------
'''
card_uid = 
file_uid = 

sys.exit("Access Denied! Invalid card format")


sys.exit("Access Denied! Card not in database")	


'''
---------------------------------------
read employee block
-------------------------------------
'''

first_name = 
last_name = 
#print(f'first {first_name}, last {last_name}')


'''
---------------------------------------
read department block
-------------------------------------
'''

department = 
#print(f'department: {department}')


'''
---------------------------------------
read clearance block
-------------------------------------
'''

clearance = 
#print(f'clearance: {clearance}')



'''
---------------------------------------
Check database entry
-------------------------------------
'''

secret = hashlib.sha3_256().hexdigest()[]


file_secret = 


card_secret = 




sys.exit("Access Denied! No clearance")

print(f'Employee: {first_name} {last_name}')
print(f'Department: {department}')
print(f'You are cleared for entry!')

