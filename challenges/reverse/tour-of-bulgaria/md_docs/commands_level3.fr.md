# Commandes V1.0

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

## Commande Print

ID de Commande : 0x4

### Description :
Afficher une chaîne de caractères dans la console.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | Size | Taille de la chaîne à afficher |
| **2** | Register | Buffer Location | Registre contenant le pointeur vers le tampon avec les données de la chaîne |
