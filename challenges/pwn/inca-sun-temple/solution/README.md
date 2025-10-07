# Les Incas: Temple du Soleil

## Write-up

Un défi classique de buffer overflow, le code secret qu'il faut rentrer est stocké juste après le buffer d'entrée. On peut donc remplacer les contenus des deux buffers du même coup avec un contenu identique, ce qui nous permet d'obtenir le flag.

Une solution automatisée se trouve [ici](./solve.py).

## Flag

`flag-caf4c732954438d6`