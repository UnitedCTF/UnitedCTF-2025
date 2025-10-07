# Bletchley Park - Level 3

# FR:

## Résolution

On remarque qu'on a 3 variables: e,n et c. Cela nous indique qu'on est face a un chiffrement RSA. 

La valeur de e est très faible (9). On peut donc utiliser l'attaque de Wiener.

On peut facilement inverser la fonction de chiffrement RSA pour retrouver le message m: [Script python](solve.py)

## Flag
`flag-b5ff1438-4bf6-4b1f-8a02-e9edd1dbb545`

# EN:

## Solution

We notice that we have 3 variables: e, n and c. This indicates that we are dealing with RSA encryption.

The value of e is very low (9). We can therefore use Wiener's attack.

We can easily reverse the RSA encryption function to retrieve the message m: [Python script](solve.py)

## Flag
`flag-b5ff1438-4bf6-4b1f-8a02-e9edd1dbb545`