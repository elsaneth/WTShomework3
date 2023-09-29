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
	
secret = hashlib.sha3_256((name+department+clearance).encode()).hexdigest()[:16]
print("secret: " + secret)

uid = "hds"
secret = hashlib.sha3_256((name+department+clearance).encode()).hexdigest()[:16]

print("Configuring ID card...")

with open(f'{uid}.txt', 'w') as f:
    f.write(f'Secret: {secret}')