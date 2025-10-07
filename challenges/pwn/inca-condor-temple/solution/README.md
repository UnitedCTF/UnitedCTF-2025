# Les Incas: Temple du Condor

## Write-up

Le défi est un exécutable programmé en C, compilé avec des stack canaries, un stack non-exécutable et en PIE. On peut assumer que ASLR est activé au niveau du système.

La vulnérabilité un peu subtile se trouve dans le décodage du "langage" Inca, qui est en fait du base64. Le décodage de base64 typique fonctionne bien, par contre, les symbols de padding (le symbole d'égalité) est mal géré.

Puisque les stack canaries sont activés, on doit faire un overflow sans écraser le canari afin d'exploiter le programme, ce qui peut bien se faire en utilisant les symboles d'égalité puisqu'ils ne font qu'incrémenter le pointeur de sortie du décodage.

Ensuite, puisqu'on peut sauter l'écriture avec des symbols d'égalité, on peut sélectivement écraser quelques bytes de l'adresse de RIP stockée sur le stack, évitant le besoin d'avoir une fuite au niveau de l'adresse.

Pour ce qui est de l'écrasement, on veut sauter à l'appel à la fonction `system("cat /flag.txt")`. Heureusement, l'adresse de cette instruction est dans le même coin que l'adresse stockée présentement, qui est une adresse dans la fonction `main`. On peut donc écraser les deux bytes les moins significatifs pour sauter à l'appel voulu. Si on écrase deux bytes, il y a quand même un nibble de l'écrasement qui est affecté par le ASLR, on peut tout simplement le bruteforcer ou essayer une valeur fixe jusqu'à ce qu'on tombe dessus.

Une solution automatisée se trouve [ici](./solve.py).

## Flag

`flag-f02ca5ef2fbed08c`