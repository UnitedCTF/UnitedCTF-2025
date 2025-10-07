import sqlite3
import hashlib
db = sqlite3.connect("../travel.db")
cur = db.cursor()

# Get the "hash" (hashes) to crack from the database
cur.execute("SELECT passhash FROM users")
hash_blob = cur.fetchone()[0]

# Split out each hash
hash_size = 256//8 # sha256 = 256 bits -> bytes
hashes = [hash_blob[i:i+hash_size] for i in range(0, len(hash_blob), hash_size)]

cracked = b""
for h in hashes:
	# Guess every ASCII character
	for i in range(128,0,-1):
		# Prepend the known characters
		guess = cracked+bytes([i])
		# Check if we got a match
		if h == hashlib.sha256(guess).digest():
			cracked = guess
			break # Go to the next hash

print(cracked.decode()) # Win!
