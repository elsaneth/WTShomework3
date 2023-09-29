from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes, toASCIIString, toASCIIBytes
import hashlib

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

print(first_name_to_bytes)
print(last_name_to_bytes)
print(department_to_bytes)
print(clearance_to_bytes)

block_nr = 9
for i in range(0,len(department_to_bytes),16):
		if (block_nr <= 10):
			#sendAPDU([0xFF, 0xD6, 0x00, block_nr, 16] + department_to_bytes[i:i+16])
			print("kirjutan" + str(block_nr))
			#move to next block for writing
		block_nr+=1

secret = hashlib.sha3_256((name+department+clearance).encode()).hexdigest()[:16]
print("secret" + secret)