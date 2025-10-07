# Influenceur 4

## Write-up

Comme indiqué dans la description, il faut utiliser le post publié sur Discord pour ce challenge. Voici la vidéo :

![juste ici](./Lancement.mp4)

Le flag est encodé en base64 et placé dans les commentaires des metadata de la vidéo.

![juste ici](./metadata.png)

Voici la string en question : `ZmxhZy1wcmVtaWVyX3ZvbF9tYWlzX2Rlcm5pZXJfcG9zdA==`

Un coup dans CyberChef et on obtient le flag :

![juste ici](./cyberchef.png)

## Flag

`flag-premier_vol_mais_dernier_post`
