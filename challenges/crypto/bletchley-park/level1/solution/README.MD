# Bletchley Park - Level 1

# FR:

## Résolution

En utilisant les indices fournis dans le message, nous pouvons déduire que nous devons utiliser le chiffrement Enigma pour décoder le message. Dans le message.txt nous avons 2 parties:
Une partie en hex: `3d3d3d3d3d54285449525049545a295f554b573a33432d31344e5f4949493a31412d3139535f49563a3234583a35455f564949493a31314b2d33433d3d3d3d3d`

Si nous la passons dans un décodeur hex, nous obtenons:
`=====T(TIRPITZ)_UKW:3C-14N_III:1A-19S_IV:24X:5E_VIII:11K-3C=====`

La deuxième partie est le flag encodé avec Enigma:

onuf-vor8rjb6-8soa-4gx4-8uk5-x1f9962zq0l5

En utilisant les paramètres trouvés dans la première partie pour configurer une machine Enigma (UKW:3C, Rotors: III, IV, VIII aux positions 1A, 19S, 11K avec les anneaux 14N, 24X, 5E), nous pouvons décoder le message encodé.

Le site [dcode.fr](https://www.dcode.fr/enigma-machine) permet de simuler une machine Enigma. En entrant les paramètres et le texte chiffré, nous obtenons le flag.

## Flag
`flag-ccb8daf6-8ffc-4cd4-8fd5-c1a9962ae0b5`

# EN:

## Solution

Using the clues provided in the message, we can deduce that we need to use the Enigma cipher to decode the message. In the message.txt we have 2 parts:
A hex part: `3d3d3d3d3d54285449525049545a295f554b573a33432d31344e5f4949493a31412d3139535f49563a3234583a35455f564949493a31314b2d33433d3d3d3d3d`

If we pass it through a hex decoder, we get:
`=====T(TIRPITZ)_UKW:3C-14N_III:1A-19S_IV:24X:5E_VIII:11K-3C=====`

The second part is the flag encoded with Enigma:

onuf-vor8rjb6-8soa-4gx4-8uk5-x1f9962zq0l5

Using the settings found in the first part to set up an Enigma machine (UKW:3C, Rotors: III, IV, VIII at positions 1A, 19S, 11K with rings 14N, 24X, 5E), we can decode the encoded message.

The site [dcode.fr](https://www.dcode.fr/enigma-machine) allows you to simulate an Enigma machine. By entering the settings and the cipher text, we get the flag

## Flag
`flag-ccb8daf6-8ffc-4cd4-8fd5-c1a9962ae0b5`