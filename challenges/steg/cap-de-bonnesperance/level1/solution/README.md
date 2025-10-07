# Cap de Bonne-Espérance - Level 1

# FR:

## Résolution

Pour résoudre ce challenge, nous pouvons utiliser un outil de stéganographie pour analyser l'image fournie. Un outil couramment utilisé est `binwalk`, qui permet d'extraire des données cachées dans des fichiers.

Lorsque nous exécutons la commande suivante dans le terminal:

```bash
binwalk -e cap_bonne_esperance.jpg
```

Nous extrayons les fichiers cachés dans l'image. Un des fichiers extraits est un zip protégé par mot de passe. En utilisant le mot de passe trouvé sur le dos de la photo ("unitedctf"), nous pouvons décompresser le fichier zip et obtenir le flag.

## Flag
`flag-e0523a83-0d51-4319-8d2b-96b31edda60d`

# EN:

## Solution

To solve this challenge, we can use a steganography tool to analyze the provided image. A commonly used tool is `binwalk`, which allows us to extract hidden data from files.

When we run the following command in the terminal:

```bash
binwalk -e cap_bonne_esperance.jpg
```

We extract the hidden files from the image. One of the extracted files is a password-protected zip file. Using the password found on the back of the photo ("unitedctf"), we can unzip the file and obtain the flag.

## Flag
`flag-e0523a83-0d51-4319-8d2b-96b31edda60d`