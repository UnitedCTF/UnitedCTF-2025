# D-8 GitHub Workflows

**`Auteur·e`** [talgarr](https://github.com/talgarr)

## Description (français)

Suite à l'ajout de son plus récent membre, l'Azerbaïdjan, l'Organisation de coopération économique D-8 a décidé de créer
un repo modèle Python pour leur collaboration. Chacun des 8 pays fondateurs — Bangladesh, Égypte, Indonésie, Iran, 
Malaisie, Nigeria, Pakistan et Turquie \— a contribué un flux de travail unique, imprégné d'éléments de sa culture et 
fièrement marqué par son drapeau. Chacun d'eux est même prêt à vous payer si vous parvenez à trouver un moyen d'obtenir 
leur drapeau. Malheureusement, seulement 4 de ces drapeaux sont présentement disponible.

Aucun ordre n'est requis, mais voici l'ordre des drapeaux du plus facile au plus complexe :
1. Bangladesh
2. Égypte
3. Iran
4. Indonésie

## Description (english)

After the addition of their newest member Azerbaijan, the D-8 Organization for Economic Cooperation decided to create
a python template for their collaboration. Each of the 8 founding countries—Bangladesh, Egypt, Indonesia, Iran,
Malaysia, Nigeria, Pakistan, and Turkey—has contributed a unique workflow, infused with part of their cultural and
proudly marked with their flag. Each of them are even ready to pay you, if you can find a way to get their flag.
Sadly, only 4 of these flags are currently available.

No order is necessary, but this is the order from easiest to most complexe flag:
1. Bangladesh
2. Egypt
3. Iran
4. Indonesia

## Solution

Solution of the challenge can be found [here](solution/).

## Setup

Create an organization to host the challenges.
Use `setup_organization.sh` to set up the challenge template. 

```shell
bash setup_organization.sh --org D8-Workflows -p chall.bundle
```

Use `generate_new_challenge.sh` for each user who wants to try the challenge. e.g. talgarr:

```shell
USERNAME="talgarr"
bash generate_new_challenge.sh \
  -o D8-Workflows \
  -r chall \
  -b chall.bundle \
  -a create \
  -f "FLAG_BANGLADESH=flag-bangladesh-ec1ec9022f3c" \
  -f "FLAG_EGYPT=flag-egypt-9312131bb234" \
  -f "FLAG_INDONESIA=flag-indonesia-68a79b1c7d55" \
  -f "FLAG_IRAN=flag-iran-e8aad09cfa0a" \
  -u $USERNAME
```

You can delete a repo using:

```shell
USERNAME="talgarr"
bash generate_new_challenge.sh -o D8-Workflows -r chall -a delete -u $USERNAME
```
