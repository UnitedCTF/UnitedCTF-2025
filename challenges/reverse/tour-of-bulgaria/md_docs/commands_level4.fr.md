# Commandes V1.1

## Commande Open

ID de Commande : 0x1

### Description :
Ouvrir un fichier.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | String | Filename | Le nom du fichier à ouvrir |
| **2** | Integer | Mode | Le mode d'ouverture du fichier (0 pour lecture, 1 pour écriture, 2 pour les deux) |
| **3** | Register | Result Register | Le registre pour stocker le descripteur de fichier |

## Commande Create Ptr

ID de Commande : 0x2

### Description :
Créer un pointeur vers un emplacement mémoire.

**<span style="color: red;">! Attention, cette commande écrase le registre r10 et r11 !</span>**

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | Size | Taille de la mémoire à allouer (doit être entre 1 et 4096 octets) |
| **2** | Register | Result Register | Registre pour stocker le pointeur |

## Commande Read

ID de Commande : 0x3

### Description :
Lire depuis un descripteur de fichier dans un pointeur.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | Size | Le nombre d'octets à lire |
| **2** | Register | File Descriptor Location | Le registre contenant le descripteur de fichier |
| **3** | Register | Buffer Location | Le registre contenant le pointeur vers le tampon où les données seront lues |

## Commande Write

ID de Commande : 0x4

### Description :
Écrire une chaîne de caractères dans un descripteur de fichier.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | Size | Le nombre d'octets à écrire |
| **2** | Register | Buffer Location | Le registre contenant le pointeur vers le tampon avec les données à écrire |
| **3** | Register | File Descriptor Location | Le registre contenant le descripteur de fichier |

## Commande Set Value

ID de Commande : 0x5

### Description :
Définir une valeur dans un registre.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | Value | La valeur à définir dans le registre |
| **2** | Register | Register | Le registre pour stocker la valeur |

## Commande Add Value

ID de Commande : 0x6

### Description :
Ajouter une valeur à un registre.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | Value | La valeur à ajouter au registre |
| **2** | Register | Register | Le registre auquel ajouter la valeur |

## Commande Create String

ID de Commande : 0xB

### Description :
Créer une chaîne de caractères dans la section de données et la charger dans un registre.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | String | String | La chaîne à créer dans la section de données |
| **2** | Register | Register | Le registre dans lequel charger le pointeur de la chaîne |
| **3** | Integer | ID | Identifiant unique pour la chaîne |
