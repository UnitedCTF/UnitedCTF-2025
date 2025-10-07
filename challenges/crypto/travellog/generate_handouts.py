from program import *
from pathlib import Path

T = " [this is not the flag]"

def move_db(folder):
	f = Path(folder)
	f.mkdir(exist_ok=True)
	Path(DATABASE_FILE).rename(f / DATABASE_FILE)

def generate_part1():
	db = db_connect()
	u = User("admin", "flag-hashcat3n473_027a50f1")
	u.register(db)

	u.add_entry(db, WELCOME_ENTRY_TITLE, WELCOME_ENTRY_CONTENT)
	u.add_entry(db, "Dev Log #1", "The app is ready! Haven't gotten my cryptography code audited yet though, "+
		"I hope nobody takes my claims seriously enough to put sensitive information like a flag in here...")

	db.close()
	move_db("part1")

def generate_part2():
	db = db_connect()
	u = User("clueless_user", "corrupted [the flag is elsewhere]")
	u.register(db)
	u.password = "fde92d8167959e46ad70a5385ddd6897"+T

	u.add_entry(db, WELCOME_ENTRY_TITLE, WELCOME_ENTRY_CONTENT)
	u.add_entry(db, "My Flag", "flag-k3y5tre4mr3use_ee810cb2")

	db.close()
	move_db("part2")

def generate_part3():
	db = db_connect()
	u = User("clueful_user", "corrupted, but you can recover it another way"+T)
	u.register(db)
	u.password = "flag-RC4timeTrAv3L_610b5d97"

	u.add_entry(db, WELCOME_ENTRY_TITLE, WELCOME_ENTRY_CONTENT)

	db.close()
	move_db("part3")

generate_part1()
generate_part2()
generate_part3()
