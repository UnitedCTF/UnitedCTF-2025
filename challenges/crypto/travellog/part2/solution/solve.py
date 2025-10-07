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

# Recover the keystream
keystream = xor(welcome_data, WELCOME_ENTRY_CONTENT.encode())

# Get the other message
cur.execute("SELECT encrypted_data FROM entries WHERE title!=?", (WELCOME_ENTRY_TITLE,))
data = cur.fetchone()[0]

# Decrypt it
print(xor(data[:-256], keystream).decode())
