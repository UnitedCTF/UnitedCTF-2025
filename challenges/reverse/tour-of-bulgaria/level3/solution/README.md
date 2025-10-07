

# Варненски Файлове (Varna Files) writeup:

# FR:

## Objectif
Le Niveau 3 introduit les opérations sur fichiers et la gestion mémoire. L'objectif est de lire un flag depuis un fichier en utilisant plusieurs commandes qui fonctionnent ensemble en séquence.

## Analyse
Ce niveau nécessite de comprendre :
- Les opérations sur fichiers (ouverture de fichiers)
- L'allocation mémoire (création de pointeurs)
- Les opérations de lecture de fichiers
- Les opérations d'impression avec des tampons

Le flag est stocké dans un fichier qui doit être ouvert, lu en mémoire, puis imprimé.

## Commandes Disponibles
- **Commande Open (0x1)** : Ouvre un fichier et retourne un descripteur de fichier
- **Commande Create Ptr (0x2)** : Alloue de la mémoire et retourne un pointeur
- **Commande Read (0x3)** : Lit des données depuis un fichier dans un tampon
- **Commande Print (0x4)** : Imprime des données depuis un tampon

## Stratégie de Solution
Nous devons exécuter les commandes en séquence :
1. Ouvrir le fichier flag pour obtenir un descripteur de fichier
2. Créer un tampon mémoire pour stocker le contenu du fichier
3. Lire le contenu du fichier dans le tampon
4. Imprimer le contenu du tampon

## Solution Étape par Étape

### Séquence de Commandes :
```
OpenCommand(b"/flag", 0, 5)
    ↓
CreatePtrCommand(45, 3)
    ↓
ReadCommand(45, 5, 3)
    ↓
PrintCommand(5, 3)
```

### Explication Détaillée :

#### Étape 1 : Ouvrir le Fichier Flag
```
OpenCommand(b"/flag", 0, 5)
```
- **b"/flag"** : Le nom de fichier comme chaîne d'octets
- **0** : Mode 0 (lecture seule)
- **5** : Stocker le descripteur de fichier dans le registre 5

#### Étape 2 : Créer un Tampon Mémoire
```
CreatePtrCommand(45, 3)
```
- **45** : Allouer 45 octets de mémoire
- **3** : Stocker le pointeur dans le registre 3
- **Note** : Cette commande écrase le registre r10/r11 durant l'exécution

#### Étape 3 : Lire le Contenu du Fichier
```
ReadCommand(45, 5, 3)
```
- **45** : Lire 45 octets
- **5** : Depuis le descripteur de fichier stocké dans le registre 5
- **3** : Dans le tampon pointé par le registre 3

#### Étape 4 : Imprimer le Flag
```
PrintCommand(5, 3)
```
- **5** : Imprimer 5 octets (longueur réelle du flag)
- **3** : Depuis le tampon pointé par le registre 3

### Bytecode :
```
01052f666c616702000002050002022d0002030003022d0002050002030004022d00020300
```

### Décomposition du Bytecode :
- `01` : Commande Open (0x1)
- `052f666c6167` : Nom de fichier "/flag" avec préfixe de longueur
- `02000002050002` : Mode 0, registre 5
- `02` : Commande Create Ptr (0x2)
- `2d0002030003` : 45 octets, registre 3
- `02` : Commande Read (0x3) [tronquée pour la brièveté]
- `04` : Commande Print (0x4) [tronquée pour la brièveté]

## Flag
`flag-af269ccc-45ba-450a-9986-4bd3941911d5`

# EN:

## Objective
Level 3 introduces file operations and memory management. The goal is to read a flag from a file using multiple commands that work together in sequence.

## Analysis
This level requires understanding:
- File operations (opening files)
- Memory allocation (creating pointers)
- File reading operations
- Print operations with buffers

The flag is stored in a file that needs to be opened, read into memory, and then printed.

## Available Commands
- **Open Command (0x1)**: Opens a file and returns a file descriptor
- **Create Ptr Command (0x2)**: Allocates memory and returns a pointer
- **Read Command (0x3)**: Reads data from a file into a buffer
- **Print Command (0x4)**: Prints data from a buffer

## Solution Strategy
We need to execute commands in sequence:
1. Open the flag file to get a file descriptor
2. Create a memory buffer to store the file contents
3. Read the file contents into the buffer
4. Print the buffer contents

## Step-by-Step Solution

### Command Sequence:
```
OpenCommand(b"/flag", 0, 5)
    ↓
CreatePtrCommand(45, 3)
    ↓
ReadCommand(45, 5, 3)
    ↓
PrintCommand(5, 3)
```

### Detailed Explanation:

#### Step 1: Open the Flag File
```
OpenCommand(b"/flag", 0, 5)
```
- **b"/flag"**: The filename as a byte string
- **0**: Mode 0 (read-only)
- **5**: Store the file descriptor in register 5

#### Step 2: Create Memory Buffer
```
CreatePtrCommand(45, 3)
```
- **45**: Allocate 45 bytes of memory
- **3**: Store the pointer in register 3
- **Note**: This command overwrites the r10/r11 registers during execution

#### Step 3: Read File Contents
```
ReadCommand(45, 5, 3)
```
- **45**: Read 45 bytes
- **5**: From the file descriptor stored in register 5
- **3**: Into the buffer pointed to by register 3

#### Step 4: Print the Flag
```
PrintCommand(5, 3)
```
- **5**: Print 5 bytes (actual flag length)
- **3**: From the buffer pointed to by register 3

### Bytecode:
```
01052f666c616702000002050002022d0002030003022d0002050002030004022d00020300
```

### Bytecode Breakdown:
- `01`: Open command (0x1)
- `052f666c6167`: Filename "/flag" with length prefix
- `02000002050002`: Mode 0, register 5
- `02`: Create Ptr command (0x2)
- `2d0002030003`: 45 bytes, register 3
- `02`: Read command (0x3) [truncated for brevity]
- `04`: Print command (0x4) [truncated for brevity]

## Flag
`flag-af269ccc-45ba-450a-9986-4bd3941911d5`