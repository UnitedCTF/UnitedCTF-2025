# Travel Log (1/3)

## Solution (français)

On vous donne le programme ainsi que la base de données d'un utilisateur.

Pour s'assurer qu'on manque rien d'évident, on peut regarder s'il y a quelque chose de suspect dans la base de données:

```
$sqlite3 travel.db
SQLite version 3.49.2
Enter ".help" for usage hints.
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users(
        id INTEGER PRIMARY KEY,
        username TEXT,
        passhash BLOB
);
INSERT INTO users VALUES(1,'admin',X'...');
CREATE TABLE entries(
        user_id INTEGER,
        title TEXT,
        encrypted_data BLOB,
        PRIMARY KEY (user_id,title)
);
INSERT INTO entries VALUES(1,'Welcome to TravelLog!',X'...');
INSERT INTO entries VALUES(1,'Dev Log #1',X'...');
COMMIT;
```

Mais non, la plupart des valeurs sont du charabia (et donc enlevés du dump ci-dessus).

> Et oui, j'ai entendu le conseil habituel, j'ai hashé le mot de passe. De plein de façons!

La description du défi et le code source du programme suggèrent fortement que vous devriez vous intéresser à cette partie du code:

```py
# TODO: make sure this is all actually safe
def my_very_good_hash(password):
	return b"".join(sha256(password[:i+1]) for i in range(len(password)))
```

Ce morceau de code prend chaque caractère du mot de passe, et hash le mot de passe jusqu'à ce caractère.

Par exemple, si on passe `"motpasse"` en argument, on obtient `sha256("m") + sha256("mo") + sha256("mot") + sha256("motp") + sha256("motpa") + sha256("motpas") + sha256("motpass") + sha256("motpasse")`

Ce qui veut dire qu'on peut déchiffrer le mot de passe hash par hash, en regardant un seul caractère à la fois.

`sha256` donne toujours un résultat de 256 bits (32 octets), donc nous commençons par prendre les 32 premiers octets, et vérifions chaque caractère possible, `hash[:32] == sha256("a")`, `hash[:32] == sha256("b")`, etc.

Une fois qu'on trouve une correspondance, on répète avec le deuxième hash, en ajoutant ce qu'on sait de la dernière étape.

On est maintenant prèt à implémenter ça en code. On commence par obtenir ce qu'on veut cracker:

```py
# Se connecter à la database
import sqlite3
db = sqlite3.connect("travel.db")
cur = db.cursor()

# Obtenir ce qu'on veut cracker
cur.execute("SELECT passhash FROM users")
hash_blob = cur.fetchone()[0]
```

Ensuite on sépare les hashs, en groupes de 32 octets:

```py
hash_size = 256//8 # sha256 = 256 bits -> 32 octets
hashes = [hash_blob[i:i+hash_size] for i in range(0, len(hash_blob), hash_size)]
```

Et puis on crack comme décrit ci-dessus:

```py
import hashlib
cracked = b""
for h in hashes:
	# Deviner chaque caractère ASCII
	for i in range(128,0,-1):
		# Ajouter aux caractères qu'on connait déja
		guess = cracked+bytes([i])
		# Voir si on a bien deviné
		if h == hashlib.sha256(guess).digest():
			cracked = guess
			break # Aller au prochain hash

print(cracked.decode()) # Et on a le mot de passe!
```

Flag: `flag-hashcat3n473_027a50f1`

## Solution (english)

You are given the program and a database.

For good measure, let's look at the database first and see if there's anything obvious:

```
$sqlite3 travel.db
SQLite version 3.49.2
Enter ".help" for usage hints.
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users(
        id INTEGER PRIMARY KEY,
        username TEXT,
        passhash BLOB
);
INSERT INTO users VALUES(1,'admin',X'...');
CREATE TABLE entries(
        user_id INTEGER,
        title TEXT,
        encrypted_data BLOB,
        PRIMARY KEY (user_id,title)
);
INSERT INTO entries VALUES(1,'Welcome to TravelLog!',X'...');
INSERT INTO entries VALUES(1,'Dev Log #1',X'...');
COMMIT;
```

Sure enough, most of the values are gibberish (and thus cleaned up in the above dump).

> I've hashed the passwords. More hashes is good, right?

The challenge description and program source strongly hints you should be looking at this part of the code:

```py
# TODO: make sure this is all actually safe
def my_very_good_hash(password):
	return b"".join(sha256(password[:i+1]) for i in range(len(password)))
```

This piece of code takes every character of the password, and hashes the password until that character.

For example, if we give it `"password"`, it returns `sha256("p") + sha256("pa") + sha256("pas") + sha256("pass") + sha256("passw") + sha256("passwo") + sha256("passwor") + sha256("password")`.

This means we can crack the password by going hash by hash, cracking a single character at a time.

`sha256` always gives a 256-bit (32-byte) results, so we start by taking the first 32 bytes, and check every possible character `hash[:32] == sha256("a")`, `hash[:32] == sha256("b")`, etc.

Once we have a match, repeat the guessing with the second hash, prepending the match we got on the last step.

Now let's implement this in code. First, get the "hash" (hashes) from the database:

```py
# Connect to the database
import sqlite3
db = sqlite3.connect("travel.db")
cur = db.cursor()

# Get what we want to crack
cur.execute("SELECT passhash FROM users")
hash_blob = cur.fetchone()[0]
```

Then, we need to split our big blob of all the hashes into a list of each actual hash:

```py
# Split out each hash
hash_size = 256//8 # sha256 = 256 bits -> 32 bytes
hashes = [hash_blob[i:i+hash_size] for i in range(0, len(hash_blob), hash_size)]
```

And then we crack the password as previously described:

```py
import hashlib
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
```

Flag: `flag-hashcat3n473_027a50f1`
