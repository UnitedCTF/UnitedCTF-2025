import sqlite3
db = sqlite3.connect("../travel.db")
cur = db.cursor()

def xor(a,b): return bytes([x^y for x,y in zip(a,b)])

# Copied from program.py
WELCOME_ENTRY_TITLE = "Welcome to TravelLog!"
WELCOME_ENTRY_CONTENT = "TravelLog is the premier end-to-end-encrypted " \
	"note-taking app for travel enthusiasts around the world!"

# Get the encrypted welcome message data
cur.execute("SELECT encrypted_data FROM entries WHERE title=?", (WELCOME_ENTRY_TITLE,))
welcome_data = cur.fetchone()[0]

# Recover the keystream and the final permutation of the state
keystream = xor(welcome_data[:-256], WELCOME_ENTRY_CONTENT.encode())
S = list(welcome_data[-256:])

# N.B. if your solution isn't in Python:
# the code below relies on Python's modulo operator behaving correctly with
# negative numbers, which is not the case in all other languages (e.g. C).

# Deduce the rest of the state (i,j)

# i is incremented each iteration of the loop; so at the end it's equal to
# len(keystream), just don't forget the first 1024 bytes have been dropped.
i = (1024 + len(keystream)) & 0xff

# Each byte of the keystream is S[t]
t = S.index(keystream[-1])

#    t = S[i] + S[j]       mod 256
# => t - S[i] = S[j]       mod 256
# => j = S.index(t - S[i]  mod 256)
j = S.index((t - S[i]) % 256)

# Just run RC4 in reverse!
for _ in range(1024+len(keystream)):
	t = (S[i] + S[j]) % 256
	S[i], S[j] = S[j], S[i]
	j = (j - S[i]) % 256
	i = (i - 1) % 256

# Because of the hilariously bad "key scheduling algorithm", we can just print
# the state and the flag will appear at the start
print(bytes(S))
