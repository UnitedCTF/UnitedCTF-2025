
# Софийски Код (Sofia Code) writeup:

# FR:

## Objectif
L'objectif du Niveau 1 est de comprendre la structure de base du langage d'assemblage personnalisé et d'exécuter une commande d'impression simple.

## Analyse
Le Niveau 1 introduit la commande la plus basique disponible dans le langage d'assemblage - la commande Print Flag. Cette commande a l'ID `0x99` et est conçue pour imprimer un flag directement.

## Commandes Disponibles
- **Commande Print Flag (0x99)** : Imprime un flag en utilisant une clé de déchiffrement et stocke la clé dans un registre.

## Stratégie de Solution
La solution est simple - nous devons seulement exécuter la commande Print Flag. Puisque c'est le niveau d'introduction, aucune logique complexe ou commandes multiples ne sont requises.

## Solution Étape par Étape

### Séquence de Commandes :
```
PrintCommand()
```

### Explication :
1. **PrintCommand()** : Cette commande s'exécute avec l'ID de commande `0x99`
   - Aucun argument n'est requis pour cette version de base
   - La commande gère l'impression du flag en interne

### Bytecode :
```
99
```

### Décomposition du Bytecode :
- `99` : ID de commande pour la commande Print Flag (0x99 en hexadécimal)

## Flag
`flag-61b156c1-4941-4e4b-8092-a78d11be7dc6`

# EN:

## Objective
The goal of Level 1 is to understand the basic structure of the custom assembly language and execute a simple print command.

## Analysis
Level 1 introduces the most basic command available in the assembly language - the Print Flag command. This command has ID `0x99` and is designed to print a flag directly.

## Available Commands
- **Print Flag Command (0x99)**: Prints a flag using a decryption key and stores the key in a register.

## Solution Strategy
The solution is straightforward - we only need to execute the Print Flag command. Since this is the introductory level, no complex logic or multiple commands are required.

## Step-by-Step Solution

### Command Sequence:
```
PrintCommand()
```

### Explanation:
1. **PrintCommand()**: This command executes with command ID `0x99`
   - No arguments are required for this basic version
   - The command handles flag printing internally

### Bytecode:
```
99
```

### Bytecode Breakdown:
- `99`: Command ID for Print Flag command (0x99 in hexadecimal)

## Flag
`flag-61b156c1-4941-4e4b-8092-a78d11be7dc6`

