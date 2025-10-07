# Travel Log (3/3)

## Solution (français)

Le programme est toujours le même, encore avec une différente base de données.

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
INSERT INTO users VALUES(1,'clueful_user',X'...');
CREATE TABLE entries(
        user_id INTEGER,
        title TEXT,
        encrypted_data BLOB,
        PRIMARY KEY (user_id,title)
);
INSERT INTO entries VALUES(1,'Welcome to TravelLog!',X'...');
COMMIT;
```

Une seule entrée cette fois-ci, juste l'entrée de bienvenue. Comme dit la description:

> l'utilisateur veut récupérer son mot de passe

On peut essayer d'utiliser notre solution de la première partie, mais comme à la deuxième, ça nous dit que c'est pas la solution: `corrupted, but you can recover it another way [this is not the flag]` (« corrompu, mais vous pouvez le récupérer d'une autre façon [ceci n'est pas le flag] »)

Il pourrait être intuitif que dans la dernière partie du défi, on s'intéresse en partie à la fonction que nous n'avons pas touché dans les autres défis:

```py
def my_key_scheduling_algorithm(password):
	S = list(range(256))
	for i, byte in zip(S, password.encode()):
		S[i], S[byte] = S[byte], S[i]
	return S
```

Cette algorithme diffère effectivement grandement de l'algorithme standard, qu'on peut voir par exemple sur [Wikipedia](https://en.wikipedia.org/wiki/RC4):

```py
def ksa_rc4_traduit_de_wikipedia(password):
	password = password.encode()
	S = list(range(256))
	j = 0
	for i in range(256):
		j = (j + S[i] + password[i % len(password)]) & 0xff
		S[i], S[j] = S[j], S[i]
	return S
```

Où le KSA standard donnerait une permutation `S` qui semble aléatoire, si on regarde le résultat du KSA dans le programme...

```py
>>> import program
>>> bytes(program.my_key_scheduling_algorithm("Testing"))
b'Testing\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRS\x00UVWXYZ[\\]^_`abcd\x01f\x06h\x04jklm\x05opqr\x02\x03uvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
```

Ça met juste notre texte au début de la permutation.

Et on nous donne la permutation! La routine de chiffrage la met à la fin du message:

```py
def my_rc4_encrypt(data, S):
	encrypted, S = rc4drop(data, S, 1024)
	return encrypted+bytes(S)
```

Cependant, si on essaie de regarder les derniers 256 octets de l'entrée de bienvenu, on vois pas le mot de passe.

La permutation qu'on obtient dans les messages chiffrés, c'est la permutation après que l'algorithme PRNG de RC4 la modifie.

Si on veut récuperer le mot de passe de l'utilisateur, donc, il faut inverser les modifications que RC4 fait à la permutation.

Ceci consiste à récuperer les valeurs de `i` et `j`, et rouler l'algorithme en inverse. L'implémentation est plus claire que le texte pour expliquer comment faire ça.

On commence toujours par récupérer une entrée chiffrée:

```py
import sqlite3
db = sqlite3.connect("travel.db")
cur = db.cursor()

# Copié depuis program.py
WELCOME_ENTRY_TITLE = "Welcome to TravelLog!"
WELCOME_ENTRY_CONTENT = "TravelLog is the premier end-to-end-encrypted " \
	"note-taking app for travel enthusiasts around the world!"

# Récupérer le message chiffré
cur.execute("SELECT encrypted_data FROM entries WHERE title=?", (WELCOME_ENTRY_TITLE,))
welcome_data = cur.fetchone()[0]
```

On a besoin de l'état interne de RC4 pour le rouler à l'envers, donc on sépare le keystream et la permutation interne `S`.

```py
def xor(a,b): return bytes([x^y for x,y in zip(a,b)])
keystream = xor(welcome_data[:-256], WELCOME_ENTRY_CONTENT.encode())
S = list(welcome_data[-256:])
```

Après on à trouver `i` et `j`. `i` est facile: il est incrémenté chaque itération de la boucle, donc forcément à la fin il est égal (modulo 256) à la longueur du keystream.

```py
i = (1024 + len(keystream)) & 0xff
```

`j` est moins facile. On peut pas le calculer directement, mais on peut le faire avec le dernier octet du keystream.

Voici la copie de l'algorithme RC4 dans le programe pour référence:

```py
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
```

Chaque octet du keystream est `S[t]`, et `t` est calculé depuis `i` et `j`. Il faut un peu d'algèbre, mais on a toutes les variables qui nous permettent de résoudre pour `j`.

```py
t = S.index(keystream[-1])
```

S'ensuit l'algèbre:

$$
\begin{align*}
         t &= S_i + S_j &\mod 256 \\
\implies S_j &= t - S_i &\mod 256 \\
\implies j &= \text{indice de } t - S_i \text{ dans } S &\mod 256 \\
\end{align*}
$$

```py
j = S.index((t - S[i]) % 256)
```

Finalement, on roule RC4 inversé comme promis (sans oublié les 1024 itérations qui ne figurent pas dans le keystream):

```py
for _ in range(1024+len(keystream)):
	t = (S[i] + S[j]) % 256
	S[i], S[j] = S[j], S[i]
	j = (j - S[i]) % 256
	i = (i - 1) % 256

# Comme on le sait, le mot de passe sera les premiers octets de la permutation!
print(bytes(S))
```

Output: `b'flag-RC4timeTrAv3L_610b5d97\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,\x04./\x15\x142\x10\x07\x17\x13\x1a8\x19:;<=>?@\x0eB\x06DEFGHIJK\x11MNOPQ\x05S\x0cUVWXYZ[\\]^\x12`\x02\x16c\x18\x0b\x00\x03h\tjk\x01\nnopq\rs\x08u\x0fwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'`

## Solution (english)

The program is still the same, and the database has once again changed:

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
INSERT INTO users VALUES(1,'clueful_user',X'...');
CREATE TABLE entries(
        user_id INTEGER,
        title TEXT,
        encrypted_data BLOB,
        PRIMARY KEY (user_id,title)
);
INSERT INTO entries VALUES(1,'Welcome to TravelLog!',X'...');
COMMIT;
```

Only one entry this time, the welcome entry. As the description states:

> Another corrupted password, but this time the user wants to recover their password

We can try to use our solution from the first part, but just like in the second part of the challenge, we get told we're not doing the right thing: `corrupted, but you can recover it another way [this is not the flag]`

It could be intuitive that in this last part of the challenge, we're going to be interested, in part, in the only one of four functions left we haven't touched in the other parts:

```py
def my_key_scheduling_algorithm(password):
	S = list(range(256))
	for i, byte in zip(S, password.encode()):
		S[i], S[byte] = S[byte], S[i]
	return S
```

This algorithm is completely different from the standard algorithm, which we can see for example on [Wikipedia](https://en.wikipedia.org/wiki/RC4):

```py
def ksa_rc4_translated_from_wikipedia(password):
	password = password.encode()
	S = list(range(256))
	j = 0
	for i in range(256):
		j = (j + S[i] + password[i % len(password)]) & 0xff
		S[i], S[j] = S[j], S[i]
	return S
```

Where the standard KSA would give a `S` permutation which seems random, if we look at the results of the KSA in the program...

```py
>>> import program
>>> bytes(program.my_key_scheduling_algorithm("Testing"))
b'Testing\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRS\x00UVWXYZ[\\]^_`abcd\x01f\x06h\x04jklm\x05opqr\x02\x03uvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
```

It just puts our password right at the start of the permutation.

And we do have access to the permutation! The custom encryption functions puts it at the end of the ciphertext:

```py
def my_rc4_encrypt(data, S):
	encrypted, S = rc4drop(data, S, 1024)
	return encrypted+bytes(S)
```

However, if we try to look at the last 256 bytes of the welcome entry, we don't see the password.

In fact, the permutation we get in the ciphertext is the permutation after it's been modified by the RC4 PRNG algorithm.

If we want to get the users's password back, then, we need to revert the changes done by the RC4 algorithm.

This consists of calculating the `i` and `j` values, and running the algorithm in reverse. An implementation is clearer than words to explain this, so let's get into it.

We again start by obtaining the ciphertext:

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
```

We need the internal state of the RC4 algorithm to run it in reverse, so we separate the keystream and `S` permutation.

```py
def xor(a,b): return bytes([x^y for x,y in zip(a,b)])
keystream = xor(welcome_data[:-256], WELCOME_ENTRY_CONTENT.encode())
S = list(welcome_data[-256:])
```

After that, `i` et `j`. `i` is easy: it's incremented every iteration of the loop, so at the end it must be equal (modulo 256) the length of the keystream.

```py
i = (1024 + len(keystream)) & 0xff
```

`j` is less easy. We can't calculate it quite so directly, but we can do it with the last byte of the keystream and some algebra.

Here's the copy of the RC4 algorithm in the program, for reference:

```py
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
```

Each byte of the keystream is `S[t]`, and `t` est calcuated from `i` et `j`. We do need a little algebra, but we now have all the variables needed to calculate `j`.

```py
t = S.index(keystream[-1])
```

The algebra follows:

$$
\begin{align*}
         t &= S_i + S_j &\mod 256 \\
\implies S_j &= t - S_i &\mod 256 \\
\implies j &= \text{index of } t - S_i \text{ in } S &\mod 256 \\
\end{align*}
$$

Or in code:

```py
j = S.index((t - S[i]) % 256)
```

Finally, we run RC4 in reverse as promised (without forgetting the 1024 iterations which are dropped from the keystream):

```py
for _ in range(1024+len(keystream)):
	t = (S[i] + S[j]) % 256
	S[i], S[j] = S[j], S[i]
	j = (j - S[i]) % 256
	i = (i - 1) % 256

# As we know, we can now just print the state and the flag will appear at the start
print(bytes(S))
```

Output: `b'flag-RC4timeTrAv3L_610b5d97\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,\x04./\x15\x142\x10\x07\x17\x13\x1a8\x19:;<=>?@\x0eB\x06DEFGHIJK\x11MNOPQ\x05S\x0cUVWXYZ[\\]^\x12`\x02\x16c\x18\x0b\x00\x03h\tjk\x01\nnopq\rs\x08u\x0fwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'`
