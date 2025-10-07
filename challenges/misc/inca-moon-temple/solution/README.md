# Les Incas: Temple de la Lune

## Write-up

Ce défi prend avantage de `strcmp` et de la génération de code secret.

Étant donné que le secret est généré avec 16 bytes aléatoires, statistiquement, le premier byte devrait être un byte nul une fois sur 256.

Puisque `strcmp` est utilisé pour la comparaison de code secret et que cette fonction arrête sa comparaison au bytes nul, on peut envoyer une ligne vide à répétition jusqu'à ce que le code soit accepté.

Une solution automatisée se trouve [ici](./solve.py).

## Flag

`flag-d474d752b3103b66`