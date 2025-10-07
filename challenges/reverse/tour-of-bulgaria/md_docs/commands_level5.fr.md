# Commandes V2.0

## Commande Create Jump

ID de Commande : 0x0

### Description :
Créer une commande de saut avec l'identifiant donné. Cette commande est utilisée pour créer une commande de saut qui peut être utilisée plus tard.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | Identifiant unique pour la commande de saut |

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

**<span style="color: red;">! Attention, cette commande écrasera le registre r10 et r11 pendant l'exécution !</span>**

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
| **1** | BigInt | Value | La valeur à ajouter au registre |
| **2** | Register | Register | Le registre auquel ajouter la valeur |

## Commande Add True Label

ID de Commande : 0x7

### Description :
Ajouter une étiquette vers laquelle sauter si une condition est vraie.

**<span style="color: red;">! Important : Vous devez avoir appelé la CreateJumpCommand avant cette commande. !</span>**

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | L'ID de la commande de saut |

## Commande Add False Label

ID de Commande : 0x8

### Description :
Ajouter une étiquette vers laquelle sauter si une condition est fausse.

**<span style="color: red;">! Important : Vous devez avoir appelé la CreateJumpCommand avant cette commande. !</span>**

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | L'ID de la commande de saut |

## Commande Compare Register

ID de Commande : 0x9

### Description :
Saute vers une étiquette selon la comparaison de deux registres et une condition.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | L'ID de la commande de saut |
| **2** | Register | Register 1 | Premier registre pour la comparaison |
| **3** | Register | Register 2 | Deuxième registre pour la comparaison |
| **4** | JumpCondition | Condition | La condition pour la comparaison |

## Commande Set Loop Counter

ID de Commande : 0xA

### Description :
Définir le compteur de boucle.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | Value | La valeur à définir pour le compteur de boucle |

## Commande Set Loop Counter From Register

ID de Commande : 0xAA

### Description :
Définir le compteur de boucle.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Register | Value | Le registre contenant la valeur à définir pour le compteur de boucle |

## Commande XOR Value

ID de Commande : 0xB

### Description :
Effectuer un XOR d'une valeur avec un registre.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | BigInt | Key | La valeur à XOR avec le registre |
| **2** | Register | Register | Le registre avec lequel effectuer le XOR |

## Commande XOR From Register

ID de Commande : 0xBB

### Description :
Effectuer un XOR d'un registre avec un registre.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Register | Key | Le registre contenant la clé à XOR |
| **2** | Register | Register | Le registre avec lequel effectuer le XOR |

## Commande Create String

ID de Commande : 0xC

### Description :
Créer une chaîne de caractères dans la section de données et la charger dans un registre.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | String | String | La chaîne à créer dans la section de données |
| **2** | Register | Register | Le registre dans lequel charger le pointeur de la chaîne |
| **3** | Integer | ID | Identifiant unique pour la chaîne |

## Commande Load From Buffer

ID de Commande : 0xD

### Description :
Charger 8 octets dans un registre.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Register | Buffer Location | Le registre contenant le pointeur du tampon |
| **2** | Integer | Offset | Le décalage dans le tampon à partir duquel lire |
| **3** | Register | Register | Le registre dans lequel charger la valeur |

## Commande Iterate Loop

ID de Commande : 0xE

### Description :
Itérer la boucle avec l'identifiant donné.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | L'ID de la boucle |

## Commande Loop Start

ID de Commande : 0xF

### Description :
Ajouter une étiquette vers laquelle boucler.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | Identifiant unique pour la boucle |

## Commande Print (WIP)

ID de Commande : 0x99

### Description :
Commande d'affichage. Actuellement affiche seulement par le pouvoir de l'imagination.

### Arguments :
| Index d'Argument | Type | Nom | Description |
|---------|---------|----------|----------|
| **1** | Register | Register | Le registre que vous voulez éventuellement afficher quand la fonction fonctionnera... |
