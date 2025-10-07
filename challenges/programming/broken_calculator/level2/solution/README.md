# Broken Calculator - Level 1

# FR:

## Objectif
Le niveau 2 est une version plus difficile du niveau 1. Il faut maintenant prendre en compte que les chiffres qu'on reçoit n'ont pas necessairement la valeur qu'ils représentent.

## Résolution

Nous pouvons réutiliser la même approche que pour le niveau 1, mais en ajoutant une étape pour mapper les chiffres reçus à leurs valeurs réelles. Si on porte attention au script du niveau 1, on remarque qu'on utilise 3 chiffres, le 0, le 1 et le plus grand chiffre disponible.

### 1: Trouver le chiffre le plus grand.
On peut envoyer une soustraction entre 2 chiffres afin de trouver lequel des 2 est le plus grand. ex: si on envoie `2-3` et qu'on reçoit `1`, on sait que 2 est plus grand que 3. On fait ça avec tout les chiffres afin de trouver le plus grand.

### 2: Trouver la position de 0.
Si on envoit une division entre 2 chiffres et qu'un des chiffres est un 0, on recevra une erreur de division par 0. On donc trouver la position de 0 avant de continuer. Pour faire cela, on soustrait notre chiffre le plus grand avec un autre chiffre. Si on reçoit comme résultat le chiffre lui-même, on sait que l'autre chiffre est un 0.

### 3: Changer notre Eval pour utiliser nos mappings.
On peut créer une fonction qui remplace les chiffres dans notre équation par leurs valeurs réelles afin d'avoir une évaluation correcte.

### 4: Générer notre équation.
On peut réutiliser la même approche que pour le niveau 1, mais en utilisant notre fonction d'évaluation modifiée.

### [Script complet](./sol.py)

## Flag
`flag-4b96f90a-ea5f-4138-afe5-c489438ac319`

# EN:

## Objective
Level 2 is a more difficult version of Level 1. You now need to account for the fact that the digits you receive don't necessarily have the value they represent.

## Solution

We can reuse the same approach as Level 1, but add a step to map the received digits to their real values. If you pay attention to the Level 1 script, you'll notice we use 3 digits: 0, 1, and the largest available digit.

### 1: Find the largest digit.
You can send a subtraction between 2 digits to find which of the 2 is larger. E.g., if you send `2-3` and receive `1`, you know that 2 is larger than 3. Do this with all digits to find the largest.

### 2: Find the position of 0.
If you send a division between 2 digits and one of the digits is a 0, you'll get a division by zero error. So you need to find the position of 0 before continuing. To do this, subtract our largest digit with another digit. If you receive the digit itself as a result, you know the other digit is a 0.

### 3: Change our Eval to use our mappings.
You can create a function that replaces the digits in your equation with their real values to get a correct evaluation.

### 4: Generate our equation.
You can reuse the same approach as Level 1, but using our modified evaluation function.

### [Complete Script](./sol.py)

## Flag
`flag-4b96f90a-ea5f-4138-afe5-c489438ac319`