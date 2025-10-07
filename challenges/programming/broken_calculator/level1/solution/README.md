# Broken Calculator - Level 1

# FR:

## Objectif
L'objectif du Niveau 1 est de résoudre une série d'équations inversées en utilisant une calculatrice "cassée" où certains boutons ne fonctionnent pas. Vous devez utiliser tous les opérateurs fonctionnels au moins une fois dans chaque équation, sans inclure le résultat cible directement, et ce dans un délai de 3 secondes par énigme.

## Résolution

Pour résoudre ce défi, vous devez :
1. Communiquer en TCP avec le challenge.
2. Savoir les nombres et opérateurs disponibles.
3. Créer une équation valide qui utilise tous les opérateurs disponibles au moins une fois.

### 1: Connexion TCP
La librairie `pwntools` en Python est idéale pour interagir avec des challenges en réseau. Elle permet de se connecter facilement à un serveur distant et d'envoyer/recevoir des données.

```python
import pwnlib.tubes.remote as remote

nc = "127.0.0.1"
port = 1437
r = remote.remote(nc, port)
```

On peut utiliser les fonctions de l'objet remote pour recevoir et envoyer des données à travers le socket.

### 2: Identifier les nombres et opérateurs disponibles
Après la connexion, le challenge envoie une ligne indiquant les nombres et opérateurs disponibles. Vous devez extraire ces informations pour savoir quels éléments vous pouvez utiliser dans votre équation.

### 3: Générer une équation valide

Il existe plusieurs façons de générer une équation valide. Voici une approche :

1. Trouver une façon d'avoir 1
2. Trouver une façon d'avoir 0
3. Trouver l'opérateur de multiplication (* ou /) si disponible
  - Si on à seulement /, on peut faire x / 1 / y pour multiplier x et y
4. Trouver l'opérateur d'addition (+ ou -) si disponible
  - Si on à seulement -, on peut faire x -- y pour additionner x et y
5. Trouver le chiffre le plus grand
6. Construire notre équation de manière recursive:
```pseudocode
créer_eq(equation, res_precedent):
    si res_precedent == res_voulu:
        retourner equation
        nouveau_res = res_precedent * max_chiffre
    Si nouveau_res > res_voulu:
        diff = nouveau_res // res_voulu
        restant = nouveau_res % res_voulu
        nouveau_res = (nouveau_res - max_chiffre) * diff + 1 * restant
        equation = (equation) - (max_chiffre répété {diff} fois) - (1 répété {restant} fois)
        créer_eq(equation, nouveau_res)
    Si nouveau_res < res_voulu:
        diff = (res_voulu - nouveau_res) // max_chiffre
        restant = (res_voulu - nouveau_res) % max_chiffre
        nouveau_res = nouveau_res + max_chiffre * diff + 1 * restant
        equation = (equation) + (max_chiffre répété {diff} fois) + (1 répété {restant} fois)
        créer_eq(equation, nouveau_res)
```

### 4: Utiliser tout les opérateurs disponibles au moins une fois
On peut ajouter a la fin de notre équation une série d'opérations qui n'affectent pas le résultat mais qui utilisent tous les opérateurs disponibles. Par exemple, si on a les opérateurs +, -, *, on peut ajouter `+1-1*1` à la fin de notre équation.

### [Script complet](./sol.py)

## Flag
`flag-7e1c825e-26c5-42d4-9dfb-3eee80ebc870`

# EN:

## Objective
The objective of Level 1 is to solve a series of reverse equations using a "broken" calculator where some buttons don't work. You must use all functional operators at least once in each equation, without including the target result directly, and all within a 3-second time limit per puzzle.

## Solution

To solve this challenge, you need to:
1. Communicate via TCP with the challenge.
2. Know the available numbers and operators.
3. Create a valid equation that uses all available operators at least once.

### 1: TCP Connection
The `pwntools` library in Python is ideal for interacting with network challenges. It allows easy connection to a remote server and sending/receiving data.

```python
import pwnlib.tubes.remote as remote

nc = "127.0.0.1"
port = 1437
r = remote.remote(nc, port)
```

You can use the remote object's functions to receive and send data through the socket.

### 2: Identify available numbers and operators
After connection, the challenge sends a line indicating the available numbers and operators. You must extract this information to know which elements you can use in your equation.

### 3: Generate a valid equation

There are several ways to generate a valid equation. Here's one approach:

1. Find a way to get 1
2. Find a way to get 0
3. Find the multiplication operator (* or /) if available
   - If you only have /, you can do x / 1 / y to multiply x and y
4. Find the addition operator (+ or -) if available
   - If you only have -, you can do x -- y to add x and y
5. Find the largest digit
6. Build your equation recursively:
```pseudocode
create_eq(equation, previous_result):
    if previous_result == target_result:
        return equation
        new_result = previous_result * max_digit
    If new_result > target_result:
        diff = new_result // target_result
        remainder = new_result % target_result
        new_result = (new_result - max_digit) * diff + 1 * remainder
        equation = (equation) - (max_digit repeated {diff} times) - (1 repeated {remainder} times)
        create_eq(equation, new_result)
    If new_result < target_result:
        diff = (target_result - new_result) // max_digit
        remainder = (target_result - new_result) % max_digit
        new_result = new_result + max_digit * diff + 1 * remainder
        equation = (equation) + (max_digit repeated {diff} times) + (1 repeated {remainder} times)
        create_eq(equation, new_result)
```
### 4: Use all available operators at least once
You can append to the end of your equation a series of operations that do not affect the result but use all available operators. For example, if you have the operators +, -, *, you can add `+1-1*1` at the end of your equation.

### [Complete Script](./sol.py)

## Flag
`flag-7e1c825e-26c5-42d4-9dfb-3eee80ebc870`