# Travel Log (2/3)

## Solution (français)

Le programme est le même que la dernière partie, mais on donne une base de données différente.

On peut essayer d'exécuter la solution de la dernière partie, mais le « mot de passe » de l'utilisateur nous indique qu'on regarde pas à la bonne place: c'est `corrupted [the flag is elsewhere]` (« corrompu [le flag est ailleurs] »).

Un `dump` de la base de données donne à peu près le même résultat qu'à la première partie:

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
INSERT INTO users VALUES(1,'clueless_user',X'...');
CREATE TABLE entries(
        user_id INTEGER,
        title TEXT,
        encrypted_data BLOB,
        PRIMARY KEY (user_id,title)
);
INSERT INTO entries VALUES(1,'Welcome to TravelLog!',X'...');
INSERT INTO entries VALUES(1,'My Flag',X'...');
COMMIT;
```

Mais il y quand même quelque chose d'utile ici, il y a une entrée « My Flag », qui est clairement celle qu'on veut déchiffrer.

L'autre entrée est également pertinente. La chose à remarquer pour ce défi est que nous utilisons du **chiffrement par flux**, RC4.

Cela veut dire que le chiffrage est effectué par un générateur de nombres pseudo-aléatoires initialisé avec une clé, de sorte que la même clé donne le même résultat, qu'on appelle le « keystream ».

Une opération d'OU exclusif (XOR) entre un message et le « keystream » donne le message chiffré... ou déchiffré, si c'était un message chiffré.

Ceci est légèrement caché dans le source du programme; la génération du keystream et l'opération XOR se produisent en même temps dans une ligne, donc le keystream n'est pas explicite: `encrypted.append(byte^S[t])`.

Cependant, dans la partie `# My cryptography` (« ma cryptographie »), il est révélé que les opérations de cryptage et de décryptage sont fondamentalement les mêmes (parce que les deux consistent à faire un XOR avec le keystream implicite):

```py
def my_rc4_encrypt(data, S):
	encrypted, S = rc4drop(data, S, 1024)
	return encrypted+bytes(S)

def my_rc4_decrypt(data, S):
	encrypted = data[:-256]
	return rc4drop(encrypted, S, 1024)[0]
```

Par ailleurs, on peut effectuer le OU exclusif entre un message en clair et chiffré, et récupérer le keystream. Et ensuite réutiliser le keystream pour déchiffrer d'autres messages.

Par coïncidence, toutes les entrées de journal utilisent la même clé de chiffrement, et nous connaissons un texte en clair: le message de bienvenue.

Il n'y a pas beaucoup de complexité cette fois-ci, alors passons directement à l'implémentation.

Nous commençons comme pour la première partie, en obtenant des données de la base de données:

```py
import sqlite3
db = sqlite3.connect("travel.db")
cur = db.cursor()

# Copié depuis program.py
WELCOME_ENTRY_TITLE = "Welcome to TravelLog!"
WELCOME_ENTRY_CONTENT = "TravelLog is the premier end-to-end-encrypted " \
	"note-taking app for travel enthusiasts around the world!"

# Obtenir la version chiffré du message de bienvenu
cur.execute("SELECT encrypted_data FROM entries WHERE title=?", (WELCOME_ENTRY_TITLE,))
welcome_data = cur.fetchone()[0]

# Obtenir le message qu'on veut déchiffrer
cur.execute("SELECT encrypted_data FROM entries WHERE title!=?", (WELCOME_ENTRY_TITLE,))
data = cur.fetchone()[0]
```

Et on poursuit avec nos deux opérations d'OU exclusif, la première pour récupérer le keystream, et une autre pour déchiffrer:

```py
def xor(a,b): return bytes([x^y for x,y in zip(a,b)])

# Récupérer le keystream
keystream = xor(welcome_data, WELCOME_ENTRY_CONTENT.encode())

# Déchiffrer
print(xor(data[:-256], keystream).decode())
```

Flag: `flag-k3y5tre4mr3use_ee810cb2`

## Solution (english)

The program is the same as in the last part, but you're given a different user's database this time.

We can try to run last part's solution, but the user's "password" tells us we're not doing the right thing: it's `corrupted [the flag is elsewhere]`.

A database dump also looks about the same:

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
INSERT INTO users VALUES(1,'clueless_user',X'...');
CREATE TABLE entries(
        user_id INTEGER,
        title TEXT,
        encrypted_data BLOB,
        PRIMARY KEY (user_id,title)
);
INSERT INTO entries VALUES(1,'Welcome to TravelLog!',X'...');
INSERT INTO entries VALUES(1,'My Flag',X'...');
COMMIT;
```

But it does seem like we get something useful here, there's an entry called `My Flag`, which is clearly the one to decrypt.

The other entry is also relevant though. The thing to notice for this challenge is that we're using the RC4 **stream cipher**.

What this means is that the encryption is done by a pseudo-random number generator initialized with a key, such that giving the same key gives the same "keystream".

The keystream is XOR-ed with a message to encrypt it, or XOR-ed with a ciphertext to decrypt a message.

This is slightly obscured in the program source; the keystream generation and XOR happen at the same time in one line, so there's no explicit keystream: `encrypted.append(byte^S[t])`.

However, in the "my cryptography" part, it is revealed that the encryption and decryption operations are basically the same (because both consist of XOR-ing with the implicit keystream):

```py
def my_rc4_encrypt(data, S):
	encrypted, S = rc4drop(data, S, 1024)
	return encrypted+bytes(S)

def my_rc4_decrypt(data, S):
	encrypted = data[:-256]
	return rc4drop(encrypted, S, 1024)[0]
```

The thing is, we can XOR a ciphertext and plaintext and recover the keystream for those bytes. And then reuse the keystream to decipher other messages which used the same key.

Coincidentally, all log entries use the same encryption key, and we know a plaintext: the welcome message.

There's not much complexity this time, so let's get straight to the implementation.

We start just like when solving the first part, by obtaining data from the database:

```py
import sqlite3
db = sqlite3.connect("travel.db")
cur = db.cursor()

# Copied from program.py
WELCOME_ENTRY_TITLE = "Welcome to TravelLog!"
WELCOME_ENTRY_CONTENT = "TravelLog is the premier end-to-end-encrypted " \
	"note-taking app for travel enthusiasts around the world!"

# Get the encrypted welcome message data
cur.execute("SELECT encrypted_data FROM entries WHERE title=?", (WELCOME_ENTRY_TITLE,))
welcome_data = cur.fetchone()[0]

# Get the message to decrypt
cur.execute("SELECT encrypted_data FROM entries WHERE title!=?", (WELCOME_ENTRY_TITLE,))
data = cur.fetchone()[0]
```

Then we just do our two XOR operations, first to recover the keystream, then to decrypt the entry using the keystream:

```py
def xor(a,b): return bytes([x^y for x,y in zip(a,b)])

# Recover the keystream
keystream = xor(welcome_data, WELCOME_ENTRY_CONTENT.encode())

# Decrypt it
print(xor(data[:-256], keystream).decode())
```

Flag: `flag-k3y5tre4mr3use_ee810cb2`
