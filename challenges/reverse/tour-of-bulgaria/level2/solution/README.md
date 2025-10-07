

# Пловдивски Пароли (Plovdiv Passwords) writeup:

# FR:

## Objectif
Le Niveau 2 s'appuie sur le Niveau 1 en introduisant des arguments à la commande Print Flag. L'objectif est d'apprendre comment passer des paramètres aux commandes dans le langage d'assemblage personnalisé.

## Analyse
Ce niveau introduit le concept d'arguments de commande. La commande Print Flag nécessite maintenant deux arguments :
1. Une clé de déchiffrement (entier)
2. Un registre pour stocker la clé

## Commandes Disponibles
- **Commande Print Flag (0x99)** : Imprime un flag en utilisant une clé de déchiffrement et un registre
  - Argument 1 : Clé (Entier) - Utilisée pour déchiffrer le flag
  - Argument 2 : Registre - Où stocker la clé

## Stratégie de Solution
Nous devons fournir la valeur de clé correcte et spécifier un registre pour la stocker. Basé sur les indices donnés dans la description du défi, la clé est `0x55`. Nous pouvons utiliser n'importe quel registre, donc nous utilisons le registre `0x1`.

## Solution Étape par Étape

### Séquence de Commandes :
```
PrintCommand(0x55, 0x1)
```

### Explication :
1. **PrintCommand(0x55, 0x1)** :
   - `0x55` : La clé de déchiffrement (85 en décimal)
   - `0x1` : Registre 1 où la clé sera stockée
   - La commande utilise ces paramètres pour déchiffrer et imprimer le flag

### Bytecode :
```
99025500020100
```

### Décomposition du Bytecode :
- `99` : ID de commande pour la commande Print Flag (0x99)
- `02` : Nombre d'arguments (2 arguments)
- `5500` : Premier argument - valeur de clé 0x55 (format little-endian)
- `02` : Indicateur de type d'argument
- `0100` : Deuxième argument - registre 0x1 (format little-endian)

## Flag
`flag-99731903-88d3-41bb-b302-fe23e10a66c9`

# EN:

## Objective
Level 2 builds upon Level 1 by introducing arguments to the Print Flag command. The goal is to learn how to pass parameters to commands in the custom assembly language.

## Analysis
This level introduces the concept of command arguments. The Print Flag command now requires two arguments:
1. A decryption key (integer)
2. A register to store the key

## Available Commands
- **Print Flag Command (0x99)**: Prints a flag using a decryption key and register
  - Argument 1: Key (Integer) - Used to decrypt the flag
  - Argument 2: Register - Where to store the key

## Solution Strategy
We need to provide the correct key value and specify a register to store it. Based on the hints given from the challenge description, the key is `0x55`. We can use any register, so we're using register `0x1`.

## Step-by-Step Solution

### Command Sequence:
```
PrintCommand(0x55, 0x1)
```

### Explanation:
1. **PrintCommand(0x55, 0x1)**:
   - `0x55`: The decryption key (85 in decimal)
   - `0x1`: Register 1 where the key will be stored
   - The command uses these parameters to decrypt and print the flag

### Bytecode:
```
99025500020100
```

### Bytecode Breakdown:
- `99`: Command ID for Print Flag command (0x99)
- `02`: Argument count (2 arguments)
- `5500`: First argument - key value 0x55 (little-endian format)
- `02`: Argument type indicator
- `0100`: Second argument - register 0x1 (little-endian format)

## Flag
`flag-99731903-88d3-41bb-b302-fe23e10a66c9`