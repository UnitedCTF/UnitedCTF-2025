import sqlite3
import hashlib
from dataclasses import dataclass

# Cryptography base
def sha256(s):
	return hashlib.sha256(s.encode()).digest()

def rc4(data, S):
	i,j = 0,0
	encrypted = []
	for byte in data:
		i = (i+1) & 0xff
		j = (j+S[i]) & 0xff
		S[i], S[j] = S[j], S[i]
		t = (S[i]+S[j]) & 0xff
		encrypted.append(byte^S[t])
	return bytes(encrypted), S

def rc4drop(data, S, drop):
	encrypted,S = rc4(bytes([0]*drop)+data, S)
	return encrypted[drop:], S

# My cryptography
# TODO: make sure this is all actually safe
def my_very_good_hash(password):
	return b"".join(sha256(password[:i+1]) for i in range(len(password)))

def my_key_scheduling_algorithm(password):
	S = list(range(256))
	for i, byte in zip(S, password.encode()):
		S[i], S[byte] = S[byte], S[i]
	return S

def my_rc4_encrypt(data, S):
	encrypted, S = rc4drop(data, S, 1024)
	return encrypted+bytes(S)

def my_rc4_decrypt(data, S):
	encrypted = data[:-256]
	return rc4drop(encrypted, S, 1024)[0]

# Database
DATABASE_FILE = "travel.db"
def db_connect():
	db = sqlite3.connect(DATABASE_FILE)
	cur = db.cursor()
	cur.execute("""
		CREATE TABLE IF NOT EXISTS users(
			id INTEGER PRIMARY KEY,
			username TEXT,
			passhash BLOB
		)
	""")
	cur.execute("""
		CREATE TABLE IF NOT EXISTS entries(
			user_id INTEGER,
			title TEXT,
			encrypted_data BLOB,
			PRIMARY KEY (user_id,title)
		)
	""")
	db.commit()
	return db

@dataclass
class User:
	username: str
	password: str
	user_id: int = -1

	def login(self, db):
		passhash = my_very_good_hash(self.password)
		cur = db.cursor()

		cur.execute("SELECT id FROM users WHERE username=? AND passhash=?",
				(self.username, passhash))
		row = cur.fetchone()
		if row is None:
			return False

		self.user_id = row[0]
		return True

	def register(self, db):
		passhash = my_very_good_hash(self.password)
		cur = db.cursor()
		cur.execute("SELECT id FROM users WHERE username=?", (self.username,))
		if cur.fetchone() is not None:
			return False

		cur.execute("INSERT INTO users(username,passhash) VALUES(?,?)",
				(self.username, passhash))
		db.commit()
		self.login(db)
		return True

	def encryption_key(self):
		return my_key_scheduling_algorithm(self.password)

	def encrypt(self, data):
		if isinstance(data, str):
			data = data.encode()
		return my_rc4_encrypt(data, self.encryption_key())

	def decrypt(self, data):
		return my_rc4_decrypt(data, self.encryption_key()).decode()

	def add_entry(self, db, title, data):
		cur = db.cursor()
		cur.execute("INSERT INTO entries(user_id, title, encrypted_data) VALUES(?,?,?)",
				(self.user_id, title, self.encrypt(data)))
		db.commit()

	def get_entries(self, db):
		cur = db.cursor()
		entries = []
		for row in cur.execute("SELECT title, encrypted_data FROM entries WHERE user_id=?", (self.user_id,)):
			entries.append((row[0], self.decrypt(row[1])))
		return entries

WELCOME_ENTRY_TITLE = "Welcome to TravelLog!"
WELCOME_ENTRY_CONTENT = "TravelLog is the premier end-to-end-encrypted " \
	"note-taking app for travel enthusiasts around the world!"

# Terminal interaction
def get_credentials():
	username = input("Username? ")
	password = input("Password? ")
	return User(username, password)

def main():
	print("Welcome to Travel Log\n")

	db = db_connect()
	logged_in_as = None
	while True:
		if logged_in_as is None:
			print("""Actions:
[1] Log in
[2] Create Account
[3] Exit
""")
			action = input().strip()
			while action not in {"1","2","3"}:
				print("Not one of the valid actions!")
				action = input().strip()
			match action:
				case "1":
					user = get_credentials()
					if user.login(db):
						logged_in_as = user
					else:
						print("Incorrect username or password!")
				case "2":
					user = get_credentials()
					if user.register(db):
						user.add_entry(db, WELCOME_ENTRY_TITLE, WELCOME_ENTRY_CONTENT)
						logged_in_as = user
					else:
						print("An account with this username already exists!")
				case "3":
					db.close()
					return
		else:
			print("""Actions:
[1] View my log
[2] Write a log entry
[3] Log out
[4] Exit
""")
			action = input().strip()
			while action not in {"1","2","3","4"}:
				print("Not one of the valid actions!")
				action = input().strip()
			match action:
				case "1":
					for title, content in logged_in_as.get_entries(db):
						print(f"Title: {title}\n{content}\n\n")
				case "2":
					title = input("Title? ")
					content = input("Content? ")
					logged_in_as.add_entry(db, title, content)
				case "3":
					logged_in_as = None
				case "4":
					db.close()
					return

if __name__ == '__main__':
	main()
