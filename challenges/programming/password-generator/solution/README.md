# Password Generator

## Write-up

Dans ce défi, à chaque fois que l'on résout une contrainte, une 
nouvelle apparaît. Dans un premier temps, on peut en valider 
quelques-unes sans forcément utiliser des techniques plus sophistiquées. 
Lorsque ça fait 4-5 niveaux que l'on réussit, il peut devenir long, 
pénible et complexe de respecter l'ensemble des clauses.

Le premier défi consiste à entrer un mot de passe respectant les 4 
premiers niveaux :

### Niveau #1
**Règle :** La longueur du mot de passe doit être entre 12 et 30 
caractères  
**Solution :** `ZZZZZZZZZZZZ`

### Niveau #2
**Règle :** Tous les caractères doivent avoir des codes ASCII entre 
35 et 122  
**Solution :** `ZZZZZZZZZZZZ` (inchangé)

### Niveau #3
**Règle :** La somme des codes ASCII des caractères doit être égale à 
18943  
**Solution :** `ZZZZZZZZZZZZ` donne seulement 7020. La stratégie est 
de mettre le caractère 'Z' jusqu'à ce que la somme soit proche de 18943 
sans le dépasser.

Ici nous avons `ZZZZZZZZZZZZZZZZZZZZ` qui donne 18900. Il manque donc 
par la suite 43 à ajouter, ce qui est faisable en ajoutant 14 et 20 
(2 × 10), soit `(Z + 14)(Z + 10)ZZZZZZZZZZZZZZZZZZ`, ce qui donne la 
solution `ZZZZZZZZZZZZZZZZZZZZ`

### Niveau #4
**Règle :** Le mot de passe doit commencer par "flag-"  
**Solution :** On utilise la même démarche que pour le niveau #3 : 
notre première solution sera donc `flag-ZZZZZZZZZZZZZZZ` ce qui donne
 une somme pondérée de 18796, ce qui fait un manque de 147. 

Comme on ne peut pas toucher aux cinq premiers caractères, on commence 
avec des multiples de six. Une décomposition possible est donc (10 × 7) 
+ (11 × 7).

Une bonne solution serait donc `flag-ZZZZ(Z + 7)(Z + 7)ZZZZZZZZZ`, ce 
qui donne la solution `flag-ZZZZaaZZZZZZZZZ`


Il est possible de continuer de cette manière pour l'ensemble des étapes, 
ce qui serait long puisqu'il y en a un total de 32. Il est possible
d'utiliser un solveur SMT pour écrire l'ensemble des clauses et sortir 
une solution respectant l'ensemble des clauses. (nous utiliserons ici Z3
https://github.com/Z3Prover/z3)

Voici un court exemple en Python pour la réécriture des quatre 
premiers niveaux :

```py
from z3 import *

s = Solver()
min_length = 12
max_length = 30

# variables que l'on tente de trouver un ensemble solution, soit les 
# caratères du mot de passe ainsi que sa taille (puisqu'elle est variable)
chars = [Int(f"c{i}") for i in range(max_length)]
length = Int("length")

# Niveau 1 : 
# La longueur du mot de passe doit être entre 12 et 30 caractères 
s.add(And(length >= min_length, length <= max_length))

# Niveau 2:
# Tous les caractères doivent avoir des codes ASCII entre 35 et 122
for i in range(max_length):
  s.add(Implies(i < length, And(chars[i] >= 35, chars[i] <= 122)))

# Niveau 3:
# La somme des codes ASCII des caractères doit être égale à 18943
weigthed_sum = Sum([chars[i] * (i+1) for i in range(max_length)])
s.add(wiegthed_sum == 18943)

# Niveau 4:
# Le mot de passe doit commencer par "flag-"
for i, c in enumerate("flag-"):
  s.add(chars[i] == ord(c))

# pour trouver une solution resptant les différentes clauses
if s.check() == sat:
  m = s.model()
  n = m[length].as_long()
  result = ''.join([chr(m[chars[i]].as_long()) for i in range(n)])
  print(result)
```

Pour l'ensemble des clauses il est possible d'aller consulter le 
[fichier solution](solve.py)


## Flag

Partie 1: `flag-ssssssTr000NNNNNNGGG-pa$$word`
Partie 2: `flag-al@mano0uAvecZ3`
