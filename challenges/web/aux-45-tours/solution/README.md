# Aux 45 tours

## Write-up

"Aux 45 tours" est un petit site web assez simple avec un seul endpoint API. L'entièreté du code se trouve dans `main.py`.

La description du défi nous dit que le flag se trouve dans `/flag.txt`. En examinant le `Dockerfile`, on voit qu'il n'est pas copié avec des permissions spécifiques (de toute façon, le serveur web roule en tant que root). On cherche donc une façon de lire un fichier arbitraire.

Allons lire le code.

### /convert
Le flux du endpoint `/convert` va comme suit:

1. Une vérification sur la taille des fichiers.
2. Une vérification sur l'extension des fichiers.
3. Le `filename` de notre téléversement est coupé pour ne préserver que le nom du fichier.
4. Les données qu'on a téléversé sont copiées dans `workdir/{notre_fichier}`.
5. Un nom de fichier de sortie aléatoire est généré.
6. **IMPORTANT**: La commande `ffmpeg` est utilisée pour faire une conversion entre le fichier d'entrée vers le fichier de sortie.
7. Le contenu du fichier de sortie est lu et retourné à l'utilisateur.

Déjà, on voit certaines choses qui pourraient être intéressantes comme des manipulations de chemin de fichier et un appel de commande. Commencons par voir ce que `ffmpeg` fait.

### ffmpeg my beloved
La page du manuel nous dit ceci:
> ffmpeg is a universal media converter. It can read a wide variety of inputs - including live grabbing/recording devices - filter, and transcode them into a plethora of output formats.

Dans notre cas, la commande est tout simplement utilisée pour faire une conversion. En effet, on voit un exemple quasi-identique dans le manuel.

> Convert an input media file to a different format, by re-encoding media streams:<br>
> `ffmpeg -i input.avi output.mp4`

L'argument `-i` spécifie le fichier d'entrée et l'argument qui suit est le fichier de sortie. En se fiant au code, on comprend qu'on a le contrôle quasi-total sur l'argument d'entrée.

En fait, est-ce vraiment *quasi*-total? On pourrait croire qu'on ne peut envoyer qu'un nom de fichier, mais en prêtant une attention particulière au code, on peut voir que l'argument d'entrée est `file.filename` et non `input_path`.

**Note:** Dans un téléversement en multipart/form-data, `filename` est une propriété entièrement contrôlée par l'utilisateur. Plusieurs cadriciels web optent de sanitiser ce paramètre par défaut pour éviter les path traversals, mais FastAPI ne le fait pas.

Nous avons donc un contrôle presque total sur ce paramètre (sauf bien sûr l'extension qui est vérifiée explicitement).

### ffmpeg partie 2
Parfait! On peut donc contrôler le paramètre d'entrée, est-ce qu'on peut spécifier `/flag` comme nom de fichier et l'exfiltrer? Pas tout à fait...

Il faut comprendre que comme tout programme digne de ce nom, ffmpeg gère correctement les erreurs et évidemment, un fichier `.txt` n'est d'aucune manière un fichier audio valide.

Par exemple, on peut essayer de convertir `/etc/passwd`:

```sh
$ ffmpeg -i /etc/passwd out.wav
ffmpeg version n7.1.1 Copyright (c) 2000-2025 the FFmpeg developers
[...]
[in#0 @ 0x558c1177a380] Error opening input: Invalid data found when processing input
Error opening input file /etc/passwd.
Error opening input files: Invalid data found when processing input
```

Si on veut être capable de sortir le flag, il faudrait donc l'insérer dans un flux de données audio valide. C'est ici qu'on fait appel au protocole [concat](https://trac.ffmpeg.org/wiki/Concatenate#protocol) supporté par ffmpeg.

### ffmpeg : concat
Le protocole `concat` de ffmpeg suit le format suivant:

```
ffmpeg -i "concat:input1.ts|input2.ts|input3.ts" -c copy output.ts
```

Il prend tous les fichiers en entrée, les concatène et traite le tout comme le fichier d'entrée. Ça semble faire ce qu'on veut.

C'est beau, mais on a encore deux contraintes:

1. Notre fichier `flag.txt` contient du texte, qu'est-ce que ça va donner si on l'insère au milieu d'un format binaire?
2. Le code vérifie que notre fichier termine avec une extension valide, visiblement, `.txt` n'y figure pas.
3. Où vas-t'on trouver un fichier valide à utiliser?

Pour le premier point, ça serait en effet un problème de simplement insérer notre flag au milieu d'un format audio typique comme `.mp3`. Par contre, des données textuelles peuvent très bien rentrer dans un format comme `.wav` qui ne contient qu'une suite d'échantillons (des chiffres, floats, etc.).

Pour le deuxième point, ce n'est pas vraiment un problème puisque `concat` supporte plus que deux fichiers, on peut donc "sandwicher" le flag entre deux noms de fichiers qui auraient des extensions valides.

Pour le dernier point, on peut prendre plusieurs approches:

1. On pourrait envoyer deux requêtes à la fois, une avec notre payload et une avec un fichier .wav quelconque. Avec un peu de chance, notre payload pourra utiliser le fichier .wav pendant qu'il est là.
2. On peut créer un URI assez spécifique dans notre `filename` pour faire le tout en une requête, cette solution sera utilisée.

### finalement

Voici un appel fonctionnel qui va nous retourner un fichier `.flac` contenant le flag.

On construit une concaténation en entrée avec `empty.wav` (téléversée dans la même requête), suivi du flag et `empty.wav` à nouveau pour avoir une extension valide.

- `empty.wav` est un fichier `.wav` minimal de 78 bytes. Un fichier normal aurait pu être utilisé.
- Le chemin du deuxième `empty.wav` est absolu. S'il ne l'était pas, `os.path.basename(file.filename)` donnerait `flag.txt|empty.wav` et on ne pourrait pas l'utiliser dans la conversion.

```python
requests.post(host + '/api/convert', files={
    'file': ('concat:empty.wav|/flag.txt|/app/workdir/empty.wav', open('empty.wav', 'rb'), 'audio/wav')
})
```

Le résultat de cette requête est un fichier `.flac`:

```sh
$ file tmp.flac
tmp.flac: FLAC audio bitstream data, 16 bit, stereo, 44.1 kHz, 27 samples
```

Le flag n'est pas lisible en clair directement, mais si on utilise ffmpeg pour le reconvertir en `.wav` et qu'on le consulte à nouveau, on peut y voir notre flag.

```sh
$ ffmpeg -i tmp.flac tmp.wav
[...]
$ strings -n 10 tmp.wav
Lavf61.7.100
flag-M3rc1Fabr1c3B3ll4rd0f8b2e15
Lavf61.7.100
```

Le script de résolution automatique peut être trouvé [ici](solve.py).

## Flag

`flag-M3rc1Fabr1c3B3ll4rd0f8b2e15`
