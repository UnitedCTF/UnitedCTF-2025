# Bletchley Park - Level 2

# FR:

## Résolution

La premiere ligne du post-it est: █I██NÈ█E ██Y:COL██SU█L█R██Z

Avec un peu de recherche on peut trouver que c'est un chiffrement de Vigenère. La clé est partiellement visible: "COL??SU?L?R??Z". En faisant un petit script python on peut bruteforcer les lettres manquantes étant donné qu'on connaisse une partie du message. 

On connait assez de lettres du message pour retrouver la clée, donc on peut créer un script qui déchiffre lettre par lettre jusqu'a ce qu'on retrouve la partie connue du message "flagunitedctf". 

Ou alors on peut juste trouver la première lettre et faire 5 boucles imbriquées :)

[Script python](solve.py)
## Flag
`flag-unitedctf-aozsgioro-toasg-oq-hifdwg`

# EN:

## Solution

The first line of the post-it is: █I██NÈ█E ██Y:COL██SU█L█R██Z

With a bit of research we can find that it's a Vigenère cipher. The key is partially visible: "COL??SU?L?R??Z". By making a small python script we can brute force the missing letters given that we know part of the message.

We know enough letters of the message to find the key, so we can create a script that decrypts letter by letter until we find the known part of the message "flagunitedctf".

Or we can just find the first letter and do 5 nested loops :)

[Python script](solve.py)

## Flag
`flag-unitedctf-aozsgioro-toasg-oq-hifdwg`