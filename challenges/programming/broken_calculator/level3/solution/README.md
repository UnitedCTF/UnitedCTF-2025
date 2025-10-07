# Broken Calculator - Level 3

# FR:

## Objectif
Le niveau 3 est une version plus difficile du niveau 2. Il faut maintenant prendre en compte que les opérateurs qu'on reçoit n'ont pas necessairement la valeur qu'ils représentent.

## Résolution

Nous pouvons réutiliser la même approche que pour le niveau 2, mais en ajoutant une étape pour mapper les opérateurs reçus à leurs valeurs réelles. Si on porte attention au script du niveau 2, on remarque qu'on à besoin d'un opérateur en particulier, la soustraction (seul opérateur qui est toujours disponible).

### 1: Quel opérateur est la soustraction?

On peut envoyer une equation en utilisant le meme chiffre 2 fois avec chaque opérateur. ex: si on envoie `2?2` pour chaque opérateur `?` et qu'on reçoit `0`, on sait que l'opérateur est la soustraction ou alors le modulo si il est disponible. On ajoute tout les opérateurs qui donnent 0 dans une liste de candidats. Si il y a plus d'un candidat, on peut envoyer une equation avec 2 chiffres différents 2 fois, en inversant les chiffres. ex: si on envoie `2?3` et `3?2` et qu'on reçoit `1` et `-1`, on sait que l'opérateur est la soustraction car le modulo ne peut pas donner de résultat négatif.

### 2: Changer notre Eval pour utiliser nos mappings.
On peut créer une fonction qui remplace les chiffres et les opérateurs dans notre équation par leurs valeurs réelles afin d'avoir une évaluation correcte.

### 3: Mêmes étapes que le niveau 2 pour créer notre équation.

### 4: Remplacer les opérateurs dans notre equation.

### [Script complet](./sol.py)

## Flag
`flag-bb36f046-2f2b-4ab0-aec0-ac45ca5fbf1b`

# EN:

## Objective
Level 3 is a more difficult version of Level 2. You now need to account for the fact that the operators you receive don't necessarily have the value they represent.

## Solution

We can reuse the same approach as Level 2, but add a step to map the received operators to their real values. If you pay attention to the Level 2 script, you'll notice we need one operator in particular: subtraction (the only operator that's always available).

### 1: Which operator is subtraction?

You can send an equation using the same digit twice with each operator. E.g., if you send `2?2` for each operator `?` and receive `0`, you know that the operator is subtraction or modulo if it's available. Add all operators that give 0 to a candidate list. If there's more than one candidate, you can send an equation with 2 different digits twice, inverting the digits. E.g., if you send `2?3` and `3?2` and receive `1` and `-1`, you know that the operator is subtraction because modulo cannot give a negative result.

### 2: Change our Eval to use our mappings.
You can create a function that replaces the digits and operators in your equation with their real values to get a correct evaluation.

### 3: Same steps as Level 2 to create our equation.

### 4: Replace the operators in our equation.

### [Complete Script](./sol.py)

## Flag
`flag-bb36f046-2f2b-4ab0-aec0-ac45ca5fbf1b`