# README
** english will follow

## Vue d’ensemble
Ce dépôt regroupe les scripts et ressources de la suite de défi **cypherpunks** sur **Solana (devnet)** :
- création d’un wallet dédié,
- dérivation/lecture des PDA,
- transaction de `claim` on-chain,
- signature d’un challenge côté client pour l’API backend.

Vous pouvez les utiliser ou pas, libre à vous. Vous devez vous procurer le IDL en json qui est disponible sur la blockchain.

Quelques conseils : 

- Gardez le même wallet tout le long des 3 défis
- Devnet n'est pas la vrai blockchain, vous pouvez vous tromper, ce n'est pas grave. Cependant, n'abusez pas des faucets, il faut respecter un rythme cohérent.
- Il y a un nombre limité de mint et donc de visa. Il est possible que j'en ajoute selon l'activité.
- Lisez requirements.txt et /setup/dependency.sh pours comprendre quels outils vous pourriez avoir besoin. Vous pouvez résoudre les défis 2 et 3 avec un script python.

---

## Fichiers et rôles

### `setup/create_ctf_wallet.sh`
Script bash pour créer rapidement un **wallet devnet** et tester le solde.
- Génére une clé JSON (`solana-keygen`).
- Configure le cluster devnet.
- Airdrop et affichage du solde.
---

### `cypherpunks/pda_check.py`
Script **lecture seule** (aucune transaction) pour vérifier l’état on-chain.
- Initialise un client Anchor (devnet), charge l’IDL et le wallet.
- Dérive les **PDA** pour l’utilisateur (seeds `b"claim"` et `b"border"` + `user_pubkey`).
- Tente un `fetch()` de `ClaimRecord` et `BorderRecord` puis affiche l’état.
- Vous pouvez vous en servir pour suivre votre avancement. 
---

### `cypherpunks/mint_my_nft.py`
Script qui demande au propriétaire actuel du NFT postcard, une copie cédée vers votre wallet.

---

### `validate_flag/get_flag.py` — Requête pour obtenir le flag 2 et/ou 3
Ce script fait la requête POST vers le serveur de validation pour obtenir le flag de manière sécurisé et unique.

---

## Challenge 2 : Demande de VISA (hint)
Allez lire le idl.json pour plus d'informations. Vous devez envoyer certaines informations au programme, voici les correspondances;
### 📑 Tableau de correspondance des comptes `claim`

| **Étiquette (code)** | **Définition / Ce que le joueur doit fournir au contrat** |
|-----------------------|-----------------------------------------------|
| `user`               | La **clé publique du joueur** (wallet qui signe la transaction). C’est le propriétaire du NFT. |
| `nft_mint`           | L’adresse du **mint du NFT** que le joueur possède (ex: le mint issu de ta Candy Machine). |
| `metadata`           | Le **PDA metadata** associé au mint, dérivé avec `["metadata", TOKEN_METADATA_PROGRAM_ID, nft_mint]`. |
| `token_account`      | Le **compte token ATA** (Associated Token Account) du joueur pour ce `nft_mint` → doit contenir au moins 1 NFT. |
| `claim_record`       | Le **PDA ClaimRecord** associé au joueur, dérivé avec `["claim", user_pubkey]`. Ce compte est créé/initialisé par le contrat si nécessaire. |
| `system_program`     | Le programme système Solana → adresse fixe : `11111111111111111111111111111111`. |
| `token_program`      | Le programme SPL Token → adresse fixe : `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`. |

---

## Challenge 3 : Passage de la frontière (hint)

Pour franchir la frontière, vous devez fournir deux informations supplémentaires :  
le numéro de la gate choisie et un pot-de-vin. Voici la correspondance des comptes :

### 📑 Tableau de correspondance des comptes `cross_border`

| **Étiquette (code)** | **Définition / Ce que le joueur doit fournir** |
|-----------------------|-----------------------------------------------|
| `signer`             | La **clé publique du joueur** (wallet qui signe la transaction). |
| `claim_record`       | Le **PDA ClaimRecord** (doit indiquer que le joueur possède déjà un visa valide). Dérivé avec `["claim", signer_pubkey]`. |
| `border_record`      | Le **PDA BorderRecord** du joueur, dérivé avec `["border", signer_pubkey]`. Ce compte est créé à la première tentative de passage. |
| `system_program`     | Le programme système de Solana → adresse fixe : `11111111111111111111111111111111`. |

### 📑 Arguments de l’instruction

| **Argument**     | **Définition / Valeur attendue vers cross_border** |
|------------------|----------------------------------|
| `chosen_gate`    | Le numéro de la gate choisi par le joueur (doit correspondre au `SECRET_GATE` défini dans le programme). |
| `bribe`          | Le montant du pot-de-vin en lamports (doit être ≥ `BRIBE_AMOUNT`). |





---

# README

## Overview
This repository contains the scripts and resources for the **Cypherpunks challenge suite** on **Solana (devnet)**:
- creating a dedicated wallet,
- deriving/reading PDAs,
- sending on-chain `claim` transactions,
- signing a client-side challenge for the backend API.

You are free to use these scripts or write your own.  
The program IDL in JSON format is available directly on-chain.

Some advice:  
- Use the **same wallet** throughout all 3 challenges.  
- Devnet is not the real blockchain: mistakes don’t matter. However, don’t abuse the faucets; keep a reasonable pace.  
- There is a limited number of mints and therefore visas. More may be added depending on activity.  
- Read `requirements.txt` and `/setup/dependency.sh` to understand which tools you might need. You can solve Challenges 2 and 3 with a Python script.  

---

## Files and Their Roles

### `setup/create_ctf_wallet.sh`
A bash script to quickly create a **devnet wallet** and test the balance.
- Generates a JSON keypair (`solana-keygen`).
- Configures the devnet cluster.
- Airdrops SOL and displays the balance.

---

### `cypherpunks/pda_check.py`
A **read-only** script (no transactions) to check on-chain state.
- Initializes an Anchor client (devnet), loads the IDL and wallet.
- Derives the **PDAs** for the user (seeds `b"claim"` and `b"border"` + `user_pubkey`).
- Attempts a `fetch()` of `ClaimRecord` and `BorderRecord` and displays their state.
- Can be used to track your progress. 

---

### `cypherpunks/mint_my_nft.py`
Script to request from the current NFT postcard owner a copy transferred to your wallet.

---

### `validate_flag/get_flag.py`
Makes a POST request to the validation server to securely and uniquely retrieve the flag for Challenge 2 and/or 3.

---

## Challenge 2: Visa Request (hint)

Check the `idl.json` for more details.  
You need to provide specific accounts to the program; here is the mapping:

### 📑 Account Mapping for `claim`

| **Label (code)** | **Definition / What the player must provide for a successfull transaction** |
|------------------|-----------------------------------------------|
| `user`           | The **public key of the player** (wallet signing the transaction). This is the NFT owner. |
| `nft_mint`       | The **mint address of the NFT** the player owns (e.g. minted from the Candy Machine). |
| `metadata`       | The **metadata PDA** associated with the mint, derived with `["metadata", TOKEN_METADATA_PROGRAM_ID, nft_mint]`. |
| `token_account`  | The **Associated Token Account (ATA)** of the player for this `nft_mint` → must hold at least 1 NFT. |
| `claim_record`   | The **ClaimRecord PDA** associated with the player, derived with `["claim", user_pubkey]`. This account is created/initialized by the contract if needed. |
| `system_program` | The Solana system program → fixed address: `11111111111111111111111111111111`. |
| `token_program`  | The SPL Token program → fixed address: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`. |

---

## Challenge 3: Border Crossing (hint)

To cross the border, you must provide additional information: the chosen gate and a bribe. Here is the mapping:

### 📑 Account Mapping for `cross_border`

| **Label (code)** | **Definition / What the player must provide for a sucessfull transaction** |
|------------------|-----------------------------------------------|
| `signer`         | The **public key of the player** (wallet signing the transaction). |
| `claim_record`   | The **ClaimRecord PDA** (must show that the player already has a valid visa). Derived with `["claim", signer_pubkey]`. |
| `border_record`  | The **BorderRecord PDA** for the player, derived with `["border", signer_pubkey]`. Created at the first crossing attempt. |
| `system_program` | The Solana system program → fixed address: `11111111111111111111111111111111`. |

### 📑 Instruction Arguments

| **Argument**   | **Definition / Expected value to cross_border** |
|----------------|---------------------------------|
| `chosen_gate`  | The gate number the player chooses (must match the `SECRET_GATE` defined in the program). |
| `bribe`        | The bribe amount in lamports (must be ≥ `BRIBE_AMOUNT`). |

---
